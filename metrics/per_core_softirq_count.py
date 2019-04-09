#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function

import time
from bcc import BPF

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#define ALERT_LIMIT 100

typedef struct alert {
    u64 timestamp;
} alert_t;

BPF_PERF_OUTPUT(alerts);
typedef struct irq_key_cpu {
    u32 vec;
    u32 cpu;
} irq_key_cpu_t;

typedef struct user_args_t {
    u32 limit;
} user_args_t;

BPF_HISTOGRAM(dist_cpu, irq_key_cpu_t);
BPF_ARRAY(user_args, user_args_t, 1);

TRACEPOINT_PROBE(irq, softirq_exit)
{
    irq_key_cpu_t cpu_key = {0};
    cpu_key.vec = args->vec;
    cpu_key.cpu = bpf_get_smp_processor_id();
    dist_cpu.increment(cpu_key);
    u64* user_val;

    u64* val = dist_cpu.lookup(&cpu_key);
    if (!val)
        return 0;

    int zero = 0;
    user_args_t* uargs = user_args.lookup(&zero);
    if (!uargs)
        return 0;

    if (*val > uargs->limit)
    {
        alert_t alert;
        alert.timestamp = bpf_ktime_get_ns();
        alerts.perf_submit(args, &alert, sizeof(alert_t));
        dist_cpu.delete(&cpu_key);
    }

    return 0;
}
"""


def update_prog_args(limit):
    prog_args = b['user_args']
    args_val = prog_args[0]
    args_val.limit = limit
    prog_args.update({0: args_val})


def handle_alert(cpu, data, size):
    alert = b['alerts'].event(data)
    print('.', end='')

    #dist_cpu.print_linear_hist(section_print_fn=vec_to_name)


def vec_to_name(vec):
    # copied from softirq_to_name() in kernel/softirq.c
    # may need updates if new softirq handlers are added
    return ["hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
            "tasklet", "sched", "hrtimer", "rcu"][vec]


b = BPF(text=bpf_text)
dist_cpu = b.get_table("dist_cpu")


update_prog_args(100)

# opens per core perf_event with perf_event_open syscall
b['alerts'].open_perf_buffer(handle_alert)

args_test = [5, 100]

exiting = 0
i = 0
while (True):
    try:
        t_end = time.time() + 3
        while time.time() < t_end:
            # non blocking poll on the perf_event fds. will call handle_alert if something is there
            b.perf_buffer_poll()

        print("updating with {}".format(args_test[i]))
        update_prog_args(args_test[i])

        i = (i + 1) % len(args_test)
    except KeyboardInterrupt:
        exiting = 1

    if exiting:
        exit()
