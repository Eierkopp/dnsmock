#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import aiohttp
import asyncio
import base64
from dnslib import DNSRecord, QTYPE
from functools import partial
import ipaddress
import logging
import struct
from dnsmocklib.tcp_connection import TCPConnection

logging.basicConfig(level=logging.DEBUG)


class DOH_Client(object):

    def __init__(self, context, address):
        self.context = context
        self.address = address
        self.context.loop.run_until_complete(self.async_init())

    async def async_init(self):
        self.session = aiohttp.ClientSession(
            headers={"Content-type": "application/dns-message"})

    def close(self):
        logging.getLogger(__name__).info("Closing DOH_Client for %s", self.address)
        self.context.loop.run_until_complete(self.session.close())

    async def query(self, dns_packet):
        async with self.session.get(self.address,
                                    params={"dns": dns_packet}) as response:
            if response.status > 299:
                return None
            if response.headers['content-type'] != "application/dns-message":
                return None

            resp = self.context.dns_parse(await response.read())
            return resp


class UDP_Client(asyncio.Protocol):

    def __init__(self, context, request, result):
        self.contex = context
        self.loop = context.loop
        self.config = context.config
        self.request = request
        self.result = result
        self.transport = None
        self.timeout = self.loop.call_later(self.config.getfloat("peer", "timeout"),
                                            self.close)

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(self.request)

    def close(self):
        self.timeout.cancel()
        if not (self.result.done() or self.result.cancelled()):
            self.result.set_result(None)
        if self.transport:
            self.transport.close()

    def datagram_received(self, data, addr):
        if not self.result.cancelled():
            self.result.set_result(context.dns_parse(data))
        self.close()

    def error_received(self, exc):
        self.close()


class TCPResponseHandler:

    def __init__(self):
        self.buffer = bytearray()
        self.pending = dict()

    def register(self, record_id, response):
        self.pending[record_id] = response

    def deregister(self, record_id):
        self.pending.pop(record_id, None)

    def flush(self):
        self.buffer.clear()
        for record_id, response in self.pending.items():
            response.cancel()
        self.pending.clear()

    def add(self, data):
        self.buffer += data
        if self.is_complete(self.buffer):
            self.buffer = self.handle(self.buffer)

    def is_complete(self, buffer):
        if len(buffer) < 2:
            return False
        return struct.unpack(">h", self.buffer[:2])[0] + 2 <= len(self.buffer)

    def handle(self, buffer):
        length = struct.unpack(">h", self.buffer[:2])[0]
        record = buffer[2:length+2]
        parsed_record = context.dns_parse(record)
        record_id = parsed_record.header.id
        response = self.pending.get(record_id, None)
        if response and not (response.done() or response.cancelled()):
            response.set_result(parsed_record)
        return buffer[length+2:]


class Context:

    def __init__(self, config, loop):
        self.loop = loop
        self.config = config
        self.timeout = config.getfloat("peer", "timeout")

        self.addresses = config.getlist("peer", "addresses")
        self.doh_addresses = config.getlist("peer", "doh_addresses")
        self.build_ip_filter()

        self.next_id = 0

        if "context" in globals():
            raise Exception("Context already created")
        global context
        context = self

    def build_ip_filter(self):
        self.ip_filter_networks = []
        if self.config.has_option("ip_filter", "ranges"):
            for net in self.config.getlist("ip_filter", "ranges"):
                self.ip_filter_networks.append(ipaddress.ip_network(net))

    def get_next_id(self):
        self.next_id = (self.next_id + 1) & 0xffff
        return self.next_id

    def dns_parse(self, record):
        """Parse a dns response and for A/AAAA
           records filter out matching resource records"""
        result = DNSRecord.parse(record)
        if result.header.rcode != 0:  # NOERROR
            return result

        num = len(result.rr)
        for i in range(num-1, -1, -1):
            r = result.rr[i]
            if QTYPE[r.rtype] in ["A", "AAAA"]:
                a = ipaddress.ip_address(r.rdata)
                for n in self.ip_filter_networks:
                    if a in n:
                        logging.getLogger(__name__).warn("DNS rebind protection, removing %s" % a)
                        del result.rr[i]
                        break
        return result

    def has_result(self, result):
        return result.header.rcode == 0

    async def udp_query(self, address, request, record_id):
        result_fut = asyncio.Future(loop=self.loop)
        try:
            await self.loop.create_datagram_endpoint(
                partial(UDP_Client, self, request, result_fut),
                remote_addr=(address, 53))
            await asyncio.wait_for(result_fut,
                                   timeout=self.timeout)
            return result_fut.result()
        except asyncio.CancelledError:
            return None
        except Exception as e:
            logging.getLogger(__name__).info("UDP query %d to %s error: %s", record_id, address, e)
            return None

    async def try_udp(self, request, record_id):
        jobs = [self.udp_query(address, request, record_id)
                for address in self.addresses]
        while jobs:
            done, jobs = await asyncio.wait(jobs,
                                            return_when=asyncio.FIRST_COMPLETED)
            for job in jobs:
                job.cancel()
            for job in done:
                record = job.result()
                if isinstance(record, DNSRecord) and record.header.tc:
                    return "truncated"
                else:
                    return record

    async def tcp_query(self, server, request, record_id):
        result_fut = asyncio.Future(loop=self.loop)
        server.handler().register(record_id, result_fut)
        try:
            await server.send(struct.pack(">h", len(request)) + request)
            await asyncio.wait_for(result_fut, timeout=self.timeout)
            return result_fut.result()
        except asyncio.CancelledError:
            return None
        except Exception as e:
            logging.getLogger(__name__).info("TCP query %d to %s error: %s",
                                             record_id, server.remote_addr(), e,
                                             exc_info=True)
            return None
        finally:
            server.handler().deregister(record_id)

    async def try_tcp(self, request, record_id):
        jobs = [self.tcp_query(server, request, record_id)
                for server in self.tcp_server]
        retval = None
        while jobs:
            done, jobs = await asyncio.wait(jobs,
                                            return_when=asyncio.FIRST_COMPLETED)
            for job in done:
                if job.result() is not None:
                    retval = job.result
                    break

        for job in jobs:
            job.cancel()
        return retval

    async def try_doh(self, record):
        orig_id = record.header.id
        record.header.id = 0
        request = record.pack()
        dns_req = base64.urlsafe_b64encode(request).decode("ascii").rstrip("=")
        jobs = [doh.query(dns_req) for doh in self.doh_server]
        retval = None
        try:
            while jobs:
                done, jobs = await asyncio.wait(jobs,
                                                timeout=self.timeout,
                                                return_when=asyncio.FIRST_COMPLETED)
                for job in done:
                    if job.result() is not None:
                        retval = job.result()
                        break

            for job in jobs:
                job.cancel()
            return retval
        finally:
            record.header.id = orig_id

    def mock_id(self, record):
        orig_id = record.header.id
        record_id = self.get_next_id()
        record.header.id = record_id
        request = record.pack()
        record.header.id = orig_id
        return request, record_id

    async def query(self, record):

        logging.getLogger(__name__).info("Send query for %s", record.q.qname)

        result = await self.try_doh(record)

        if result is None:
            request, record_id = self.mock_id(record)

            result = await self.try_udp(request, record_id)
            if result == "truncated":
                result = await self.try_tcp(request, record_id)

        if isinstance(result, DNSRecord):
            result.header.id = record.header.id
            return result
        else:
            return None

        return result

    def start(self):
        self.tcp_server = []
        for ip in self.addresses:
            response_handler = TCPResponseHandler()
            server = TCPConnection(self.loop,
                                   ip,
                                   53,
                                   self.config.getfloat("peer", "timeout"),
                                   response_handler)
            self.tcp_server.append(server)

        self.doh_server = []
        for address in self.doh_addresses:
            server = DOH_Client(self, address)
            asyncio
            self.doh_server.append(server)

    def stop(self):
        for doh_srv in self.doh_server:
            doh_srv.close()
