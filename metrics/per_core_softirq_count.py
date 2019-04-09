
#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function

import time
from bcc import BPF
import argparse

parser = argparse.ArgumentParser(
    description="Summarize soft irq event time as histograms.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-l", "--limit", type=int, default=0,
    help="alert on hard limit")
parser.add_argument('-i', "--interval", type=int, default=1000,
    help="collection interval, in milliseconds")
args = parser.parse_args()

bpf_softirq_limit = """
#include <uapi/linux/ptrace.h>

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
if args.limit:
    b = BPF(text=bpf_softirq_limit)

    update_prog_args(100)
    b['alerts'].open_perf_buffer(handle_alert)

    args_test = [5, 100]

    interval = 1000
elif args.interval:
    print('starting in interval mode')
    b = BPF(text=bpf_softirq_collect)

    interval = args.interval

# i = 0
while (1):
    try:
        t_end = time.time() + interval
        if args.limit:
            while time.time() < t_end:
                b.perf_buffer_poll()
        elif args.interval:
            time.sleep(interval / 1000)

        dist_cpu = b.get_table("dist_cpu")
        dist_cpu.print_linear_hist("irqs")

        if args.interval:
            dist_cpu.clear()

        # print("updating with {}".format(args_test[i]))
        # update_prog_args(args_test[i])
        # i += 1
        # i = i % len(args_test)
    except KeyboardInterrupt:
        break


def update_prog_args(limit):
    prog_args = b['user_args']
    args_val = prog_args[0]
    args_val.limit = limit
    prog_args.update({0: args_val})

def handle_alert(cpu, data, size):
    alert = b['alerts'].event(data)
    print('.', end='')
    #print('too many interrupts on CPU #{} at time {}!'.format(cpu, alert.timestamp))

def vec_to_name(vec):
    # copied from softirq_to_name() in kernel/softirq.c
    # may need updates if new softirq handlers are added
    return ["hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
            "tasklet", "sched", "hrtimer", "rcu"][vec]