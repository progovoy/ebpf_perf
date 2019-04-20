import asyncio
from bcc import BPF
from dataclasses import dataclass, field, InitVar
from typing import Dict, List, Any
import os
import time


bpf_softirq_limit = f"""
#include <uapi/linux/ptrace.h>

typedef struct alert {{
    u64 timestamp;
}} alert_t;

BPF_PERF_OUTPUT(alerts);

typedef struct irq_key_cpu {{
    u32 vec;
    u32 cpu;
}} irq_key_cpu_t;

typedef struct user_limits_t {{
    int timer_irq_per_second[{os.cpu_count()}];
}} user_limits_t;

BPF_HISTOGRAM(dist_cpu, irq_key_cpu_t);

// An array of 1 user_limits_t element
BPF_ARRAY(user_limits, user_limits_t, 1);

TRACEPOINT_PROBE(irq, softirq_exit)
{{
    irq_key_cpu_t cpu_key = {{0}};
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

    //if (ulimits->timer_irq_per_second[cpu_key.cpu] == -1)
    //    return 0;
    
    if (cpu_key.vec == 1)
        return 0;
        
    //if (*val > ulimits->timer_irq_per_second[cpu_key.cpu]){{
    if (*val > 5){{
        alert_t alert;
        alert.timestamp = bpf_ktime_get_ns();

        alerts.perf_submit(args, &alert, sizeof(alert_t));
        dist_cpu.delete(&cpu_key);
    }}
    
    return 0;
}}
"""

bpf_softirq_collect = """
#include <uapi/linux/ptrace.h>

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

    return 0;
}
"""


def load(args):
    if type(args) is not dict:
        raise ValueError('args must be a dictionary')

    if 'limits' in args and 'timer_irq_per_sec' in args['limits']:
        timer_irq_limits = [-1] * os.cpu_count()

        for core, val in args['limits']['timer_irq_per_sec'].items():
            if not 0 <= core < len(timer_irq_limits):
                raise ValueError(
                    f'{core} not in cpu range 0 - {len(timer_irq_limits) - 1}'
                )

            timer_irq_limits[core] = val

        args['limits']['timer_irq_per_sec'] = timer_irq_limits

    if 'limits':
        limits = Limits(**args['limits'])
        args['limits'] = limits

    instance = SoftIRQs(**args)

    return instance


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
            update_limits(self.bpf_handler, self.limits)
            self.bpf_handler['alerts'].open_perf_buffer(SoftIRQs._handle_alert)
        else:
            self.bpf_handler = BPF(text=bpf_softirq_collect)

        self.main_task = asyncio.create_task(self.run())
        self.can_run.set()

    @staticmethod
    def _handle_alert(cpu, data, size):
        print('.', end='')

    async def run(self):
        while self.can_run:
            self.bpf_handler.perf_buffer_poll()

            await asyncio.sleep(self.interval / 1000)

            dist_cpu = self.bpf_handler.get_table("dist_cpu")
            dist_cpu.print_linear_hist("irqs", section_print_fn=vec_to_name)

    def stop(self):
        self.can_run.clear()


def update_limits(bpf_handler, limit: Limits):
    ulimits = bpf_handler['user_limits']
    limits_val = ulimits[0]

    for i in range(len(limits_val.timer_irq_per_second)):
        limits_val.timer_irq_per_second[i] = limit.timer_irq_per_sec[i]

    ulimits.update({0: limits_val})


def vec_to_name(vec):
    # copied from softirq_to_name() in kernel/softirq.c
    # may need updates if new softirq handlers are added
    return ["hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
            "tasklet", "sched", "hrtimer", "rcu"][vec]
