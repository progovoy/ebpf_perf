
#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function

import time
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./softirqs            # sum soft irq event time
    ./softirqs -d         # show soft irq event time as histograms
    ./softirqs 1 10       # print 1 second summaries, 10 times
    ./softirqs -NT 1      # 1s summaries, nanoseconds, and timestamps
"""
parser = argparse.ArgumentParser(
    description="Summarize soft irq event time as histograms.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")

parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
if args.nanoseconds:
    factor = 1
    label = "nsecs"
else:
    factor = 1000
    label = "usecs"
debug = 0

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

b = BPF(text=bpf_text)

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

update_prog_args(100)

b['alerts'].open_perf_buffer(handle_alert)

exiting = 0 if args.interval else 1
dist_cpu = b.get_table("dist_cpu")

args_test = [5, 100]
i = 0

while (1):
    try:
        t_end = time.time() + 3
        while time.time() < t_end:
            b.perf_buffer_poll()

        print("updating with {}".format(args_test[i]))
        update_prog_args(args_test[i])
        i += 1
        i = i % len(args_test)
    except KeyboardInterrupt:
        exiting = 1

    countdown -= 1
    if exiting or countdown == 0:
        exit()
