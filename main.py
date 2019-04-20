import asyncio
import sys
import argparse
import logging
import yaml
from importlib import import_module

LOGGER = logging.getLogger()


def _load_metrics(metrics):
    metrics_dict = {}

    for metric in metrics:
        mod = import_module(f'metrics.{metric}')
        metrics_dict[metric] = mod.load(metrics[metric]['args'])

    return metrics_dict


async def main():
    parser = argparse.ArgumentParser(
        description='Arguments for the eBPF perf tool'
    )
    parser.add_argument(
        '--conf_file',
        required=True,
        help='A path to the conf.yml file'
    )

    args = parser.parse_args()

    req = yaml.load(open(args.conf_file))
    metrics = _load_metrics(req['metrics'])

    while True:
        await asyncio.sleep(10)

if __name__ == '__main__':
    ret = asyncio.run(main())
    sys.exit(ret)
