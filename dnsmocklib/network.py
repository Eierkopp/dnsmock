#!python3
# -*- coding: utf-8 -*-

from functools import partial
import ifaddr
import logging
from pprint import pformat
import socket
import struct
import asyncio
from dnslib import DNSRecord, QR, QTYPE, RCODE

from dnsmocklib import dns_client

logging.basicConfig(level=logging.DEBUG)


def qt_qn(record):
    return QTYPE[record.q.qtype], str(record.q.qname).rstrip(".")


class UDP_Handler(asyncio.DatagramProtocol):

    def __init__(self, loop, config, handler):
        asyncio.DatagramProtocol.__init__(self)
        self.loop = loop
        self.config = config
        self.protocol_handler = handler()
        self.transport = None
        self.closed = asyncio.Event()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.closed.set()

    async def wait_closed(self):
        await self.closed.wait()

    def close(self):
        self.transport.close()

    def datagram_received(self, data, addr):
        self.loop.create_task(
            self.protocol_handler.handle(
                data,
                addr,
                partial(self.send_response, addr=addr)))

    def send_response(self, response, addr):
        if response:
            self.transport.sendto(response, addr)


class TCP_Handler(asyncio.Protocol):
    def __init__(self, loop, config, handler):
        asyncio.Protocol.__init__(self)
        self.loop = loop
        self.config = config
        self.protocol_handler = handler()
        self.buffer = bytearray()
        self.transport = None
        self.conn_timeout = None

    def connection_made(self, transport):
        self.transport = transport

    def close(self):
        self.conn_busy(False)
        if self.transport:
            self.transport.close()

    def conn_busy(self, busy=True):
        if self.conn_timeout:
            self.conn_timeout.cancel()
        if busy:
            self.conn_timeout = self.loop.call_later(
                self.config.getfloat("local", "conn_timeout"),
                self.close)

    def handle(self, data):
        self.loop.create_task(
            self.protocol_handler.handle(
                data,
                self.transport.get_extra_info('peername'),
                self.send_response))

    def send_response(self, response):
        if response:
            self.transport.write(struct.pack(">h", len(response)))
            self.transport.write(response)

    def data_received(self, data):
        self.conn_busy()
        self.buffer += data
        if len(self.buffer) > 2:
            length = struct.unpack(">h", self.buffer[:2])[0]
            if length+2 >= len(self.buffer):
                data = self.buffer[2:length+2]
                self.buffer = self.buffer[length+2:]
                self.handle(data)

    def eof_received(self):
        self.close()


async def open_server(loop, config, protocol_handler, interfaces, port):
    udp_endpoints = []
    tcp_endpoints = []
    ip_addresses = set()
    for i in ifaddr.get_adapters():
        if i.name in interfaces:
            for ip in i.ips:
                if isinstance(ip.ip, tuple):  # ipv6addr, flowinfo, scope
                    ip_addresses.add((f"{ip.ip[0]}%{ip.ip[2]}", socket.AF_INET6))
                else:
                    ip_addresses.add((ip.ip, socket.AF_INET))

    for ip, family in ip_addresses:
        try:
            logging.getLogger(__name__).info("Create endpoint %s:%s", ip, port)
            udp_endpoints.append(
                await loop.create_datagram_endpoint(
                    partial(UDP_Handler, loop, config, protocol_handler),
                    family=family,
                    local_addr=(ip, port)
                )
            )
            tcp_endpoints.append(
                await loop.create_server(
                    partial(TCP_Handler, loop, config, protocol_handler),
                    host=ip,
                    port=port,
                    family=family,
                    reuse_address=True
                )
            )
        except Exception:
            logging.getLogger(__name__).warning(
                "Not listening on %s:%s", i, port, exc_info=True)

    server_list = []
    for srv in udp_endpoints:
        server, handler = srv
        handler.server = server
        server_list.append(handler)
    for srv in tcp_endpoints:
        server_list.append(srv)
    return server_list


class DNS_Handler:

    def __init__(self, context):
        self.context = context

    def generic_error(self, record):
        logging.getLogger(__name__).debug(
            "Returning generic error for %s: %s" % qt_qn(record))
        response = record.reply()
        response.header.rcode = RCODE.SERVFAIL
        return response.pack()

    async def handle(self, data, addr, callback):
        record = DNSRecord.parse(data)
        if QR[record.header.qr] != "QUERY":
            logging.getLogger(__name__).info("Not a QUERY: %s" % record)
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


class Context:

    def __init__(self, parent_config, parent_loop):
        self.server = []
        self.loop = parent_loop
        self.config = parent_config

    def query(self, record):
        return self.client_context.query(record)

    async def close_all(self):
        for s in self.server:
            s.close()
        for s in self.server:
            await s.wait_closed()

    async def rebind(self):
        await self.close_all()

        self.server = await open_server(self.loop,
                                        self.config,
                                        partial(DNS_Handler, context=self),
                                        self.config.getlist("local", "interfaces"),
                                        self.config.getint("local", "port"))
        logging.getLogger(__name__).info("Server running: %s", pformat(self.server))

    def start(self, mocks):
        self.mocks = mocks.mocks
        self.cache = mocks.cache
        self.client_context = dns_client.Context(self.config, self.loop)
        self.client_context.start()

        self.loop.run_until_complete(self.rebind())

    def stop(self):
        self.client_context.stop()
        self.loop.run_until_complete(self.close_all())
