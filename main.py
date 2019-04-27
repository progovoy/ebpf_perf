import asyncio
import sys
import argparse
import logging
import yaml
from importlib import import_module

from aiohttp import web

import metrics_exporter

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
LOGGER.addHandler(handler)


def _load_metrics(metrics):
    metrics_dict = {}

    for metric in metrics:
        LOGGER.info(f'Loading metric {metric} with args:')
        LOGGER.info(metrics[metric]['args'])

        mod = import_module(f'metrics.{metric}')
        metrics_dict[metric] = mod.load(metrics[metric]['args'])

    return metrics_dict


def mount_metrics_exporter(app, metric_sources):
    exporter = metrics_exporter.MetricsExporter(metric_sources)
    app.add_routes([web.get('/metrics', exporter)])
    return exporter


async def main():
    parser = argparse.ArgumentParser(
        description='Arguments for the eBPF perf tool'
    )
    parser.add_argument(
        '-c',
        '--conf_file',
        required=True,
        help='A path to the conf.yml file'
    )

    args = parser.parse_args()
    config = yaml.load(open(args.conf_file), Loader=yaml.Loader)

    metrics = _load_metrics(config['metrics'])

    for metric in metrics.values():
        LOGGER.info(f'Running metric gatherer {metric.__class__.__name__}')

    app = web.Application()
    mount_metrics_exporter(app, metrics)
    web_task = web._run_app(app)

    # Await all tasks together so we get exceptions
    tasks = [web_task] + [asyncio.create_task(metric.run()) for metric in metrics.values()]
    await asyncio.gather(*tasks)


if __name__ == '__main__':
    ret = asyncio.run(main())
    sys.exit(ret)
