#!python3
# -*- coding: utf-8 -*-

import asyncio
from functools import partial
import ifaddr
import logging
from pprint import pformat
import socket
import struct

from dnslib import DNSRecord, QR, QTYPE, RCODE

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger


def qt_qn(record):
    return QTYPE[record.q.qtype], str(record.q.qname).rstrip(".")


class UDP_Handler(asyncio.DatagramProtocol):

    def __init__(self, config, handler, local_address):
        asyncio.DatagramProtocol.__init__(self)
        self.config = config
        self.protocol_handler = handler()
        self.local_address = local_address
        self.transport = None
        self.closed = asyncio.Event()

    def __repr__(self):
        return "%s listening on %s" % (__class__.__name__, self.local_address)

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.closed.set()

    async def wait_closed(self):
        await self.closed.wait()

    def close(self):
        self.transport.close()

    def datagram_received(self, data, addr):
        asyncio.create_task(
            self.protocol_handler.handle(
                data,
                addr,
                partial(self.send_response, addr=addr)))

    def send_response(self, response, addr):
        if response:
            self.transport.sendto(response, addr)


class TCP_Handler:
    def __init__(self, config, handler, reader, writer):
        self.reader = reader
        self.writer = writer
        self.config = config
        self.protocol_handler = handler
        self.timeout = config.getfloat("local", "conn_timeout")
        self.buffer = b""

    def close(self):
        log(__name__).debug("Closing TCP connection")
        self.writer.close()

    async def run(self):
        while True:
            try:
                request = await asyncio.wait_for(self.read_request(), timeout=self.timeout)
                if request is None:
                    return
                await self.protocol_handler.handle(request,
                                                   self.writer.transport.get_extra_info('peername'),
                                                   self.send_response)
            except asyncio.TimeoutError:
                return

    async def read_request(self):
        while self.req_length(self.buffer) == -1 and not self.reader.at_eof():
            self.buffer += await self.reader.read(128)
        req_length = self.req_length(self.buffer)
        if req_length == -1:
            return None
        else:
            request = self.buffer[2:req_length]
            self.buffer = self.buffer[req_length:]
            return request

    def req_length(self, buffer):
        """Return -1 if request is not complete,
        length otherwise"""
        if len(buffer) < 2:
            return -1
        next_length = struct.unpack(">h", buffer[:2])[0] + 2
        if next_length <= len(buffer):
            return next_length
        else:
            return -1

    def send_response(self, response):
        if response:
            self.writer.write(struct.pack(">h", len(response)))
            self.writer.write(response)


class DNS_Handler:

    def __init__(self, context):
        self.context = context

    def generic_error(self, record):
        log(__name__).debug(
            "Returning generic error for %s: %s" % qt_qn(record))
        response = record.reply()
        response.header.rcode = RCODE.SERVFAIL
        return response.pack()

    async def handle(self, data, addr, callback):
        record = DNSRecord.parse(data)
        if QR[record.header.qr] != "QUERY":
            log(__name__).info("Not a QUERY: %s" % record)
            callback(None)
            return

        response = self.context.mocks.resolve(record, addr)
        if response is not None:
            callback(response)
            return

        result = await self.context.query(record)
        if isinstance(result, DNSRecord):
            for rr in result.rr:
                if rr.ttl < self.context.config.getint("local", "min_ttl"):
                    rr.ttl = self.context.config.getint("local", "min_ttl")
            self.context.mocks.filter_response(result)
            self.context.cache.add(record, result)
            callback(result.pack())
            return
        else:
            callback(self.generic_error(record))
            return


class DNS_Server:

    def __init__(self, parent_config):
        self.server = []
        self.config = parent_config

    def query(self, record):
        return self.client.query(record)

    async def close_all(self):
        for s in self.server:
            s.close()
        for s in self.server:
            await s.wait_closed()

    async def tcp_client_connected(self, reader, writer):
        handler = TCP_Handler(self.config, DNS_Handler(self), reader, writer)
        await handler.run()
        handler.close()

    async def open_server(self, protocol_handler, interfaces, port):
        udp_endpoints = []
        tcp_endpoints = []
        ip_addresses = set()
        loop = asyncio.get_running_loop()
        for i in ifaddr.get_adapters():
            if i.name in interfaces:
                for ip in i.ips:
                    if isinstance(ip.ip, tuple):  # ipv6addr, flowinfo, scope
                        ip_addresses.add((f"{ip.ip[0]}%{ip.ip[2]}", socket.AF_INET6))
                    else:
                        ip_addresses.add((ip.ip, socket.AF_INET))

        for ip, family in ip_addresses:
            try:
                log(__name__).info("Create endpoint %s:%s", ip, port)
                udp_endpoints.append(
                    await loop.create_datagram_endpoint(
                        partial(UDP_Handler, self.config, protocol_handler, (ip, port)),
                        family=family,
                        local_addr=(ip, port)
                    )
                )
                tcp_endpoints.append(
                    await asyncio.start_server(
                        self.tcp_client_connected,
                        host=ip,
                        port=port,
                        family=family,
                        reuse_address=True
                    )
                )
            except Exception:
                log(__name__).warning(
                    "Not listening on %s:%s", i, port, exc_info=True)

        server_list = []
        for srv in udp_endpoints:
            server, handler = srv
            handler.server = server
            server_list.append(handler)
        for srv in tcp_endpoints:
            server_list.append(srv)
        return server_list

    async def rebind(self):
        await self.close_all()

        self.server = await self.open_server(partial(DNS_Handler, context=self),
                                             self.config.getlist("local", "interfaces"),
                                             self.config.getint("local", "port"))
        log(__name__).info("Server running:\n%s", pformat(self.server))

    async def start(self, mocks, client):
        self.mocks = mocks.mocks
        self.cache = mocks.cache
        self.client = client

        await self.rebind()

    async def stop(self):
        await self.close_all()
