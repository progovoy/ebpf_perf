from aiohttp import web


class MetricsExporter(object):
    def __init__(self, sources):
        self._sources = sources

    async def __call__(self, request):
        text = ''
        for k, v in self._sources.items():
            text = f'{text}{v.export_metrics()}\n'

        return web.Response(text=text)
