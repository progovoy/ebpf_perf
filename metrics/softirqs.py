import asyncio
from bcc import BPF
from dataclasses import dataclass, field
from typing import List, Any
import os
import numpy


bpf_softirq_limit = """
#include <uapi/linux/ptrace.h>

typedef struct alert {
    u64 timestamp;
} alert_t;

typedef struct user_limits_t {
    int timer_irq_per_second[256];
} user_limits_t;

// An array of 1 user_limits_t element
BPF_ARRAY(user_limits, user_limits_t, 1);
BPF_PERF_OUTPUT(alerts);

typedef struct irq_key_cpu {
    u32 vec;
    u32 cpu;
} irq_key_cpu_t;

BPF_HISTOGRAM(dist_cpu, irq_key_cpu_t);

TRACEPOINT_PROBE(irq, softirq_exit)
{
    irq_key_cpu_t cpu_key = {0};
    cpu_key.vec = args->vec;
    cpu_key.cpu = bpf_get_smp_processor_id();
    dist_cpu.increment(cpu_key);
    u64* user_val;
    
    // Get the count on this specific interrupt for current core
    u64* val = dist_cpu.lookup(&cpu_key);
    if (!val)
        return 0;
        
    int zero = 0;
    user_limits_t* ulimits = user_limits.lookup(&zero);
    if (!ulimits)
        return 0;

    u8 core = bpf_get_smp_processor_id();
    if (ulimits->timer_irq_per_second[core] == -1)
        return 0;
    
    // This magic number(1) is actually the number of the timer irq
    if (cpu_key.vec != 1)
        return 0;
        
    if (*val > ulimits->timer_irq_per_second[core]){
        alert_t alert;
        alert.timestamp = bpf_ktime_get_ns();

        alerts.perf_submit(args, &alert, sizeof(alert_t));
        dist_cpu.delete(&cpu_key);
    }
    
    return 0;
}
"""

SOFT_IRQS = [
    "hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
    "tasklet", "sched", "hrtimer", "rcu"
]


def load(args):
    if type(args) is not dict:
        raise ValueError('args must be a dictionary')

    if 'limits' in args and 'timer_irq_per_sec' in args['limits']:
        timer_irq_limits = [-1] * os.cpu_count()

        for core, val in args['limits']['timer_irq_per_sec'].items():
            if not 0 <= core < len(timer_irq_limits):
                print(f'Core #{core} specified in configuration does not exist, ignoring...')
                continue

            timer_irq_limits[core] = val

        args['limits']['timer_irq_per_sec'] = timer_irq_limits

    if 'limits' in args:
        limits = Limits(**args['limits'])
        args['limits'] = limits

    instance = SoftIRQs(**args)

    return instance


def _vec_to_name(vec):
    # copied from softirq_to_name() in kernel/softirq.c
    # may need updates if new softirq handlers are added
    return SOFT_IRQS[vec]

@dataclass
class Limits:
    timer_irq_per_sec: List[int] = None


@dataclass
class SoftIRQs:
    bpf_handler: Any = field(default=None, init=False)
    interval: int = 1000
    limits: Limits = None
    can_run: asyncio.Event = field(default=asyncio.Event(), init=False)

    def __post_init__(self):
        if self.limits is not None:
            self.bpf_handler = BPF(text=bpf_softirq_limit)
            self._update_limits()
            self.bpf_handler['alerts'].open_perf_buffer(self._handle_alert)
        else:
            self.update_limits(Limits(timer_irq_per_sec=[-1] * os.cpu_count()))

        self.main_task = asyncio.create_task(self.run())
        self.can_run.set()

        self._hist_matrix = numpy.zeros((os.cpu_count(), len(SOFT_IRQS), 0))

    def _save_histogram(self):
        new_shape = list(self._hist_matrix.shape)
        new_shape[2] = new_shape[2] + 1
        self._hist_matrix.resize(new_shape, refcheck=False)
        last_idx = self._hist_matrix.shape[2] - 1

        dist_cpu = self.bpf_handler.get_table("dist_cpu")
        for k, v in dist_cpu.items():
            self._hist_matrix[k.cpu][k.vec][last_idx] = v.value

        self._std_matrix = numpy.std(self._hist_matrix, axis=2)
        print(self._std_matrix)

    def _handle_alert(self, cpu, data, size):
        alert = self.bpf_handler['alerts'].event(data)
        #print(f'Too many interrupts on CPU #{cpu} at time {alert.timestamp}!')

    def update_limits(self, limits: Limits):
        self.limits = limits
        self._update_limits()

    def _update_limits(self):
        ulimits = self.bpf_handler['user_limits']
        limits_val = ulimits[0]

        for i in range(len(self.limits.timer_irq_per_sec)):
            limits_val.timer_irq_per_second[i] = self.limits.timer_irq_per_sec[i]

        ulimits.update({0: limits_val})

    async def run(self):
        while self.can_run:
            self.bpf_handler.perf_buffer_poll()

            await asyncio.sleep(self.interval / 1000)

            self._save_histogram()

    def stop(self):
        self.can_run.clear()
