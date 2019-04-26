import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any, List
import numpy as np
from bcc import BPF

from metrics.metric import Metric, SlidingWindow, Latest

_bpf_softirq_limit = """
#include <uapi/linux/ptrace.h>

typedef struct alert {
    u32 vec;
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
        
    if (*val > ulimits->timer_irq_per_second[core]) {
        alert_t alert;
        alert.vec = cpu_key.vec;
        alert.timestamp = bpf_ktime_get_ns();

        alerts.perf_submit(args, &alert, sizeof(alert_t));
        dist_cpu.delete(&cpu_key);
    }
    
    return 0;
}
"""

_SOFT_IRQS = [
    "hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
    "tasklet", "sched", "hrtimer", "rcu"
]

LOGGER = logging.getLogger()


def load(args):
    if type(args) is not dict:
        raise ValueError('args must be a dictionary')

    if 'limits' in args and 'timer_irq_per_sec' in args['limits']:
        timer_irq_limits = [-1] * os.cpu_count()

        for core, val in args['limits']['timer_irq_per_sec'].items():
            if not 0 <= core < len(timer_irq_limits):
                LOGGER.warning(
                    f'Core #{core} specified in configuration does not exist, '
                    f'ignoring...'
                )

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
    return _SOFT_IRQS[vec]


@dataclass
class Limits:
    timer_irq_per_sec: List[int] = None


@dataclass
class SoftIRQs:
    interval: int = 1000
    sliding_window_size: int = 100
    std_factor: float = 3
    limits: Limits = None

    _bpf_handler: Any = field(default=None, init=False)

    _can_run: asyncio.Event = field(default=asyncio.Event(), init=False)

    _cpu_count = os.cpu_count()
    _shape = (_cpu_count, len(_SOFT_IRQS))

    def __post_init__(self):
        self._define_metrics()

        if self.limits is not None:
            self._bpf_handler = BPF(text=_bpf_softirq_limit)
            self._update_limits()
            self._bpf_handler['alerts'].open_perf_buffer(self._handle_alert)
        else:
            self.update_limits(
                Limits(timer_irq_per_sec=[-1] * self._cpu_count)
            )

        self._can_run.set()

    def _define_metrics(self):
        class_name = self.__class__.__name__

        LOGGER.info(f'Defining metric: {class_name}')
        self._metric = Metric(
            name=f'{class_name}Metric',
            shape=self._shape,
            collection_algorithm=SlidingWindow(
                shape=self._shape,
                window_size=self.sliding_window_size,
                dim_calc=np.std
            )
        )

        LOGGER.info(f'Defining alert: {class_name}')
        self._alert = Metric(
            name=f'{class_name}Alert',
            shape=self._shape,
            collection_algorithm=Latest(shape=self._shape)
        )

        for core in range(self._shape[0]):
            for vec in range(self._shape[1]):
                metric_name = f'cpu_{core}_irq_{_vec_to_name(vec)}_std'
                alert_name = f'cpu_{core}_irq_{_vec_to_name(vec)}_alert'

                LOGGER.info(f'Dimension: {metric_name} Alert: {alert_name}')

                self._metric.set_dim_name((core, vec), metric_name)
                self._alert.set_dim_name((core, vec), alert_name)

        self.exported_metrics = [self._metric, self._alert]

    def _save_histogram(self):
        dist_cpu = self._bpf_handler.get_table("dist_cpu")
        for k, v in dist_cpu.items():
            self._metric.update_dim((k.cpu, k.vec), v.value)

        dist_cpu.clear()

    def _handle_alert(self, core, data, size):
        alert = self._bpf_handler['alerts'].event(data)
        self._alert.update_dim((core, alert.vec), alert.timestamp)

    def update_limits(self, limits: Limits):
        self.limits = limits
        self._update_limits()

    def _update_limits(self):
        ulimits = self._bpf_handler['user_limits']
        limits_val = ulimits[0]

        for i in range(len(self.limits.timer_irq_per_sec)):
            limits_val.timer_irq_per_second[i] =\
                self.limits.timer_irq_per_sec[i]

        ulimits.update({0: limits_val})

    async def run(self):
        while self._can_run:
            self._bpf_handler.perf_buffer_poll()

            await asyncio.sleep(self.interval / 1000)

            self._save_histogram()

    def stop(self):
        self._can_run.clear()
