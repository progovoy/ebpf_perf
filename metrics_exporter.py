from aiohttp import web
import asyncio


class MetricsExporter(object):
    def __init__(self, sourcres):
        self._sources = sourcres
        self._app = web.Application()
        self._app.add_routes([web.get('/metrics', self._handle_metrics)])

        self._main_task = asyncio.create_task(web._run_app(self._app))

    async def _handle_metrics(self, request):
        text = ''
        for k, v in self._sources.items():
            text = f'{text}{v.export_metrics()}\n'

        return web.Response(text=text)
