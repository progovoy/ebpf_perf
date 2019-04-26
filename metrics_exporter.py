from aiohttp import web


class MetricsExporter(object):
    def __init__(self, sources):
        self._sources = sources

    async def __call__(self, request):
        text = ''

        for source in self._sources.values():
            for metric in source.exported_metrics:
                for dim in metric.export_dims():
                    text += f'{dim.name} {dim.value}\n'

        return web.Response(text=text)
