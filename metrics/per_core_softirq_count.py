
#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
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

typedef struct irq_key_cpu {
    u32 vec;
    u32 cpu;
} irq_key_cpu_t;

BPF_HISTOGRAM(dist_cpu, irq_key_cpu_t);

TRACEPOINT_PROBE(irq, softirq_exit)
{
    irq_key_cpu_t cpu_key = {0};

    // store
    cpu_key.vec = args->vec;
    cpu_key.cpu = bpf_get_smp_processor_id();
    dist_cpu.increment(cpu_key);

    // store as sum or histogram
    
    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

def vec_to_name(vec):
    # copied from softirq_to_name() in kernel/softirq.c
    # may need updates if new softirq handlers are added
    return ["hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
            "tasklet", "sched", "hrtimer", "rcu"][vec]

print("Tracing soft irq event time... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist_cpu = b.get_table("dist_cpu")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print(dir(dist_cpu))

    for k,v in dist_cpu.items():
        pass

    dist_cpu.print_linear_hist(section_print_fn=vec_to_name)

    dist_cpu.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()