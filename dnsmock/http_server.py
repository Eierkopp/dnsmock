#!/usr/bin/env python3

import argparse
from aiohttp import web, ClientSession
from aiohttp.web_runner import AppRunner, TCPSite
from dnslib import DNSRecord, DNSQuestion, QTYPE

from .dns_server import DNS_Server
from .mocks import Mocks
from .logger import log

SHUTDOWN_TIMEOUT = 5
BACKLOG = 5


class HttpServer:
    def __init__(self, config: argparse.Namespace, mocks: Mocks, server: DNS_Server) -> None:
        self.config = config
        self.mocks = mocks
        self.server = server

    async def handle_set(self, request: web.Request) -> web.Response:
        try:
            self.mocks.handle_updates()
            record = request.match_info.get("record")
            if record is None:
                return web.Response(status=400, reason="Missing record")
            qname = request.match_info.get("qname")
            if qname is None:
                return web.Response(status=400, reason="Missing qname")
            value = await request.json()
            qt = QTYPE.reverse[record]
            query = DNSRecord(q=DNSQuestion(qname, qt))
            response = query.reply()
            self.mocks.add_record(record, response, qname, value)
            self.mocks.cache.add(query, response)
            return web.Response(status=200)
        except Exception as e:
            log(__name__).error("Call to /set failed: %s", e, exc_info=True)
            return web.Response(status=500)

    async def handle_flush(self, request: web.Request) -> web.Response:
        try:
            self.mocks.cache.forget()
            return web.Response(status=200)
        except Exception as e:
            log(__name__).error("Call to /flush failed: %s", e, exc_info=True)
            return web.Response(status=500)

    async def handle_update(self, request: web.Request) -> web.Response:
        try:
            await self.server.rebind()
            max_status = 0
            urls = self.config.dyndns_update_urls
            for url in urls:
                log(__name__).info("Updating url %s", url)
                async with ClientSession() as session:
                    async with session.get(url) as response:
                        log(__name__).info("call to %s, status=%d", url, response.status)
                        await response.read()
                        max_status = max(response.status, max_status)

            for hostname in self.config.dyndns_hostnames:
                self.mocks.cache.forget(hostname)

            return web.Response(status=max_status)
        except Exception:
            log(__name__).error("call failed", exc_info=True)
            return web.Response(status=500)

    async def run_app(self, app: web.Application, host: str, port: int) -> None:
        self.runner = AppRunner(app)

        await self.runner.setup()

        sites = []
        log(__name__).info("Created HTTP endpoint %s:%d", host, port)
        sites.append(
            TCPSite(
                self.runner,
                host,
                port,
                shutdown_timeout=SHUTDOWN_TIMEOUT,
                backlog=BACKLOG,
                reuse_address=True,
            )
        )

        for site in sites:
            await site.start()

    async def stop(self) -> None:
        await self.runner.cleanup()

    async def start(self) -> None:
        app = web.Application()

        app.router.add_get("/update", self.handle_update)
        app.router.add_get("/flush", self.handle_flush)
        app.router.add_post("/set/{record}/{qname}", self.handle_set)

        await self.run_app(app, self.config.dyndns_host, self.config.dyndns_port)
