#!/usr/bin/env python3

from functools import partial
import logging
from aiohttp import web, ClientSession
from aiohttp.web_runner import AppRunner, TCPSite

logging.basicConfig(level=logging.DEBUG)

SHUTDOWN_TIMEOUT = 5
BACKLOG = 5


async def handle_update(context, request):
    try:
        await context.network.rebind()
        max_status = 0
        urls = context.config.getlist("dyndns", "update_urls")
        for url in urls:
            logging.getLogger(__name__).info("Updating url %s", url)
            async with ClientSession() as session:
                async with session.get(url) as response:
                    logging.getLogger(__name__).info(
                        "call to %s, status=%d", url, response.status)
                    await response.read()
                    max_status = max(response.status, max_status)

        for hostname in context.config.getlist("dyndns", "hostnames"):
            context.cache.forget(hostname)

        return web.Response(status=max_status)
    except Exception:
        logging.getLogger(__name__).error("call failed", exc_info=True)
        return web.Response(status=500)


async def handle_flush(cache, request):
    try:
        cache.forget()
        return web.Response(status=200)
    except Exception as e:
        logging.getLogger(__name__).error(
            "Call to /flush failed: %s", e, exc_info=True)
        return web.Response(status=500)


class Context:

    def __init__(self, config, loop):
        self.config = config
        self.loop = loop

    def run_app(self, app, host, port):
        self.runner = AppRunner(app)

        self.loop.run_until_complete(self.runner.setup())

        sites = []
        logging.getLogger(__name__).info(
            "Created HTTP endpoint %s:%d", host, port)
        sites.append(TCPSite(self.runner, host, port,
                             shutdown_timeout=SHUTDOWN_TIMEOUT,
                             backlog=BACKLOG,
                             reuse_address=True,
                             reuse_port=True))

        for site in sites:
            self.loop.run_until_complete(site.start())

    def shutdown(self):
        self.loop.run_until_complete(self.runner.cleanup())

    def start(self, network, mocks):
        self.network = network
        self.cache = mocks.cache
        app = web.Application()

        app.router.add_get('/update', partial(handle_update, self))
        app.router.add_get('/flush', partial(handle_flush, self.cache))

        self.run_app(app,
                     self.config.get("dyndns", "host"),
                     self.config.getint("dyndns", "port"))
