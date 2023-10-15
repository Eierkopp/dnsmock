#!python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from aiohttp import web
from aiohttp.web_runner import AppRunner, TCPSite
import argparse
import asyncio
import base64
from functools import partial
import ifaddr
import logging
from pprint import pformat
import socket
import ssl
import struct
from typing import cast, List, Optional, Set, Tuple

from dnslib import DNSRecord, QR, RCODE

from .dns_client import DNS_Client
from .mocks import Mocks, qt_qn
from .leakybucket import LeakyBucket

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger


SHUTDOWN_TIMEOUT = 5
BACKLOG = 5

Address = Tuple[str, int]


class DNS_Handler(ABC):
    def __init__(self, config: argparse.Namespace, mocks: Mocks, client: DNS_Client) -> None:
        self.config = config
        self.schedule = self.mk_schedule()
        self.mocks = mocks
        self.cache = mocks.cache
        self.client = client

    def mk_schedule(self) -> List[Tuple[float, int]]:
        retval = list()
        for sched in self.config.dos_schedule:
            interval_str, count_str = sched.split(",")
            retval.append((float(interval_str), int(count_str)))
        return retval

    @abstractmethod
    async def close(self) -> None:
        pass

    def generic_error(self, record: DNSRecord) -> bytes:
        log(__name__).debug("Returning generic error for %s: %s" % qt_qn(record))
        response = record.reply()
        response.header.rcode = RCODE.SERVFAIL
        return cast(bytes, response.pack())

    async def query(self, record: DNSRecord) -> Optional[DNSRecord]:
        return await self.client.query(record)

    async def handle(self, data: bytes, addr: Address) -> bytes | None:
        record = DNSRecord.parse(data)
        if QR[record.header.qr] != "QUERY":
            log(__name__).info("Not a QUERY: %s" % record)
            return None

        response = None
        try:
            response = self.mocks.resolve(record, addr)
        except self.mocks.DropException:
            return None
        except Exception:
            log(__name__).error("Error in resolve", exc_info=True)
            return self.generic_error(record)

        if response is not None:
            return response

        result = await self.query(record)
        if isinstance(result, DNSRecord):
            for rr in result.rr:
                if rr.ttl < self.config.local_min_ttl:
                    rr.ttl = self.config.local_min_ttl
            self.mocks.filter_response(result)
            bucket = LeakyBucket(self.schedule)
            self.cache.add(record, result, bucket)
            return cast(bytes, result.pack())
        else:
            return self.generic_error(record)


class UDP_Handler(asyncio.DatagramProtocol, DNS_Handler):
    def __init__(
        self, config: argparse.Namespace, mocks: Mocks, client: DNS_Client, local_address: Address
    ) -> None:
        DNS_Handler.__init__(self, config, mocks, client)
        asyncio.DatagramProtocol.__init__(self)
        self.local_address = local_address
        self.transport: Optional[asyncio.transports.DatagramTransport] = None
        self.closed = asyncio.Event()

    def __repr__(self) -> str:
        return "%s listening on %s" % (self.__class__.__name__, self.local_address)

    def connection_made(self, transport: asyncio.transports.BaseTransport) -> None:
        self.transport = cast(asyncio.transports.DatagramTransport, transport)

    def connection_lost(self, exc: Exception | None) -> None:
        self.closed.set()

    async def close(self) -> None:
        if self.transport:
            self.transport.close()
        await self.closed.wait()
        log(__name__).info("UDP Server closed")

    def datagram_received(self, data: bytes, addr: Address) -> None:
        async def process_datagram(data: bytes, addr: Address) -> None:
            response = await self.handle(data, addr)
            if response:
                self.send_response(response, addr)

        asyncio.create_task(process_datagram(data, addr))

    def send_response(self, response: bytes, addr: Address) -> None:
        if self.transport:
            self.transport.sendto(response, addr)


class TCP_Handler(DNS_Handler):
    def __init__(self, config: argparse.Namespace, mocks: Mocks, client: DNS_Client):
        DNS_Handler.__init__(self, config, mocks, client)
        self.timeout = config.local_conn_timeout
        self.server: Optional[asyncio.Server] = None

    def set_server(self, server: asyncio.Server) -> None:
        self.server = server

    async def close(self) -> None:
        log(__name__).debug("Closing TCP connection")
        if self.server:
            self.server.close()

    def __repr__(self) -> str:
        return "%s listening on %s" % (
            self.__class__.__name__,
            self.server.sockets[0].getsockname() if self.server else "NOTHING",
        )

    async def client_connected(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while True:
            try:
                request = await asyncio.wait_for(self.read_request(reader), timeout=self.timeout)
                if request is None:
                    return
                response = await self.handle(request, writer.transport.get_extra_info("peername"))
                if response:
                    writer.write(struct.pack(">h", len(response)))
                    writer.write(response)
            except asyncio.TimeoutError:
                return

    async def read_request(self, reader: asyncio.StreamReader) -> bytes | None:
        buffer = b""
        while self.req_length(buffer) == -1 and not reader.at_eof():
            buffer += await reader.read(128)
        req_length = self.req_length(buffer)
        if req_length == -1:
            return None
        else:
            request = buffer[2:req_length]
            buffer = buffer[req_length:]
            return request

    def req_length(self, buffer: bytes) -> int:
        """Return -1 if request is not complete,
        length otherwise"""
        if len(buffer) < 2:
            return -1
        next_length = cast(int, struct.unpack(">h", buffer[:2])[0] + 2)
        if next_length <= len(buffer):
            return next_length
        else:
            return -1


class DOH_Handler(DNS_Handler):
    def __init__(self, config: argparse.Namespace, mocks: Mocks, client: DNS_Client) -> None:
        DNS_Handler.__init__(self, config, mocks, client)
        self.loop = asyncio.get_running_loop()
        self.port = config.local_doh_port
        self.path = config.local_doh_path
        self.ssl = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.ssl.load_cert_chain(config.local_doh_cert, config.local_doh_key)
        app = web.Application()
        app.router.add_get(self.path, self.handle_get)
        app.router.add_post(self.path, self.handle_post)
        self.runner = AppRunner(app)
        asyncio.create_task(self.setup())

    async def setup(self) -> None:
        await self.runner.setup()
        self.site = TCPSite(
            self.runner,
            None,
            self.port,
            ssl_context=self.ssl,
            shutdown_timeout=SHUTDOWN_TIMEOUT,
            backlog=BACKLOG,
            reuse_address=True,
            reuse_port=True,
        )
        await self.site.start()
        log(__name__).info("DOH_Handler started")

    def __repr__(self) -> str:
        return "%s listening on https://0.0.0.0:%d%s" % (
            self.__class__.__name__,
            self.port,
            self.path,
        )

    async def handle_get(self, request: web.Request) -> web.Response:
        if request.content_type != "application/dns-message":
            return web.Response(status=400, reason="Wrong content type")
        try:
            req = base64.urlsafe_b64decode(request.query["dns"])
            res = await self.handle(req, request._transport_peername)
            resp = web.Response(
                status=200,
                reason="OK",
                content_type="application/dns-message",
                body=res,
            )
            return resp
        except Exception as e:
            log(__name__).info("Error: %s", e, exc_info=True)
            return web.Response(status=400, reason="Malformed request")

    async def handle_post(self, request: web.Request) -> web.Response:
        if request.content_type != "application/dns-message":
            return web.Response(status=400, reason="Wrong content type")
        try:
            req = await request.read()
            res = await self.handle(req, request._transport_peername)
            resp = web.Response(
                status=200,
                reason="OK",
                content_type="application/dns-message",
                body=res,
            )
            return resp
        except Exception as e:
            log(__name__).info("Error: %s", e, exc_info=True)
            return web.Response(status=400, reason="Malformed request")

    async def close(self) -> None:
        await self.site.stop()
        await self.runner.cleanup()
        log(__name__).info("DOH Server closed")


class DNS_Server:
    def __init__(self, config: argparse.Namespace, mocks: Mocks, client: DNS_Client) -> None:
        self.config = config
        self.mocks = mocks
        self.cache = mocks.cache
        self.client = client
        self.server: List[DNS_Handler] = []

    async def close_all(self) -> None:
        for s in self.server:
            await s.close()

    def fetch_ip_addresses(self) -> List[Tuple[str, int]]:
        ip_addresses: Set[Tuple[str, int]] = set()
        for i in ifaddr.get_adapters():
            if i.name in self.config.local_interfaces:
                for ip in i.ips:
                    if isinstance(ip.ip, tuple):  # ipv6addr, flowinfo, scope
                        ip_addresses.add((f"{ip.ip[0]}%{ip.ip[2]}", socket.AF_INET6))
                    else:
                        ip_addresses.add((ip.ip, socket.AF_INET))
        return list(ip_addresses)

    async def open_server(self) -> List[DNS_Handler]:
        server_list: List[DNS_Handler] = []
        loop = asyncio.get_running_loop()
        ip_addresses = self.fetch_ip_addresses()
        port = self.config.local_port
        for ip_addr, family in ip_addresses:
            try:
                log(__name__).info("Create endpoint %s:%s", ip_addr, port)
                _, handler = await loop.create_datagram_endpoint(
                    partial(UDP_Handler, self.config, self.mocks, self.client, (ip_addr, port)),
                    family=family,
                    local_addr=(ip_addr, port),
                )
                server_list.append(handler)

                tcp_handler = TCP_Handler(self.config, self.mocks, self.client)
                server = await asyncio.start_server(
                    tcp_handler.client_connected,
                    host=ip_addr,
                    port=port,
                    family=family,
                    reuse_address=True,
                )
                tcp_handler.set_server(server)
                server_list.append(tcp_handler)
            except Exception as e:
                log(__name__).warning("Not listening on %s:%s", ip_addr, port)
                log(__name__).debug("Not listening on %s:%s", ip_addr, port, exc_info=e)

        try:
            if self.config.local_doh_port > 0:
                server_list.append(DOH_Handler(self.config, self.mocks, self.client))
        except Exception:
            log(__name__).warning("Not listening on %s:%s", ip_addr, port)
        return server_list

    async def rebind(self) -> None:
        await self.close_all()
        self.server = await self.open_server()
        log(__name__).info("Server running:\n%s", pformat(self.server))

    async def start(self) -> None:
        await self.rebind()

    async def stop(self) -> None:
        await self.close_all()
