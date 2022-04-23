#!/usr/bin/env python3

from functools import partial
import logging
from aiohttp import web, ClientSession
from aiohttp.web_runner import AppRunner, TCPSite

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger

SHUTDOWN_TIMEOUT = 5
BACKLOG = 5


async def handle_update(context, request):
    try:
        await context.network.rebind()
        max_status = 0
        urls = context.config.getlist("dyndns", "update_urls")
        for url in urls:
            log(__name__).info("Updating url %s", url)
            async with ClientSession() as session:
                async with session.get(url) as response:
                    log(__name__).info(
                        "call to %s, status=%d", url, response.status)
                    await response.read()
                    max_status = max(response.status, max_status)

        for hostname in context.config.getlist("dyndns", "hostnames"):
            context.cache.forget(hostname)

        return web.Response(status=max_status)
    except Exception:
        log(__name__).error("call failed", exc_info=True)
        return web.Response(status=500)


async def handle_flush(cache, request):
    try:
        cache.forget()
        return web.Response(status=200)
    except Exception as e:
        log(__name__).error(
            "Call to /flush failed: %s", e, exc_info=True)
        return web.Response(status=500)


class HttpServer:

    def __init__(self, config):
        self.config = config

    async def run_app(self, app, host, port):
        self.runner = AppRunner(app)

        await self.runner.setup()

        sites = []
        log(__name__).info(
            "Created HTTP endpoint %s:%d", host, port)
        sites.append(TCPSite(self.runner, host, port,
                             shutdown_timeout=SHUTDOWN_TIMEOUT,
                             backlog=BACKLOG,
                             reuse_address=True,
                             reuse_port=True))

        for site in sites:
            await site.start()

    async def stop(self):
        await self.runner.cleanup()

    async def start(self, network, mocks):
        self.network = network
        self.cache = mocks.cache
        app = web.Application()

        app.router.add_get('/update', partial(handle_update, self))
        app.router.add_get('/flush', partial(handle_flush, self.cache))

        await self.run_app(app,
                           self.config.get("dyndns", "host"),
                           self.config.getint("dyndns", "port"))
