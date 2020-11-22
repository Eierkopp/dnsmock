#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import aiohttp
from aiosocketpool import AsyncConnectionPool, AsyncTcpConnector
import asyncio
import base64
from dnslib import DNSRecord, QTYPE, RCODE
import functools
import ipaddress
import logging
import socket
import struct
import time

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger


def log_exception(function):

    module = function.__module__
    myname = module + "." + function.__name__
    exclog = log(module)

    if asyncio.iscoroutinefunction(function):

        @functools.wraps(function)
        async def wrapper(*args, **kwargs):
            try:
                return await function(*args, **kwargs)
            except Exception:
                exclog.error("Exception in " + myname, exc_info=True)

        return wrapper

    else:

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception:

                exclog.error("Exception in " + myname, exc_info=True)

        return wrapper


class DNS_Client:

    def __init__(self, interface, server):
        self.interface = interface
        self.server = server

    async def start(self):
        raise NotImplementedError()

    async def stop(self):
        raise NotImplementedError()

    async def query(self, record):
        raise NotImplementedError()


class DOH_Client(DNS_Client):

    def __init__(self, interface, server):
        super().__init__(interface, server)

    async def start(self):
        log(__name__).info("Starting DOH client for address %s", self.server)
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.interface.timeout),
            headers={"Content-type": "application/dns-message"})

    async def stop(self):
        log(__name__).info("Closing DOH client for %s", self.server)
        await self.session.close()

    @log_exception
    async def query(self, dns_packet, req_id):
        async with self.session.get(self.server,
                                    params={"dns": dns_packet}) as response:
            if response.status > 299:
                return None
            if response.headers['content-type'] != "application/dns-message":
                return None

            resp = self.interface.dns_parse(await response.read())
            return resp


class UDP_Client(DNS_Client, asyncio.DatagramProtocol):

    def __init__(self, interface, server):
        super().__init__(interface, server)
        self.requests = dict()

    async def start(self):
        log(__name__).info("Starting UDP client for address %s", self.server)
        loop = asyncio.get_event_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            self,
            family=socket.AF_INET,
            remote_addr=(self.server, 53)
        )

    async def stop(self):
        log(__name__).info("Closing UDP client for address %s", self.server)
        self.transport.close()

    def __call__(self):
        return self  # Protocol factory will always return this instance

    def datagram_received(self, data, address):
        resp = self.interface.dns_parse(data)
        req_id = resp.header.id
        future = self.requests.pop(req_id, None)
        if future is not None:
            future.set_result(resp)

    def deregister(self, req_id):
        self.requests.pop(req_id, None)

    @log_exception
    async def query(self, record, req_id):
        future = asyncio.futures.Future()
        self.requests[req_id] = future
        self.transport.sendto(record)
        await future
        return future.result()


class TCP_Client(DNS_Client):

    def __init__(self, interface, server):
        super().__init__(interface, server)
        self.pool = AsyncConnectionPool(
            factory=AsyncTcpConnector,
            reap_connections=True,
            max_lifetime=10,
            max_size=2
        )

    async def start(self):
        log(__name__).info("Starting TCP client for address %s", self.server)

    async def stop(self):
        log(__name__).info("Closing TCP client for address %s", self.server)
        self.pool.reap_all()
        self.pool.stop_reaper()

    def is_complete(self, buffer):
        if len(buffer) < 2:
            return False
        return struct.unpack(">h", buffer[:2])[0] + 2 <= len(buffer)

    @log_exception
    async def query(self, record, req_id):
        buffer = b""
        async with self.pool.connection(host=self.server, port=53) as conn:
            await conn.sendall(struct.pack(">h", len(record)))
            await conn.sendall(record)
            while not self.is_complete(buffer):
                try:
                    data = await asyncio.wait_for(conn.recv(128), timeout=self.interface.timeout)
                    if not data:
                        return None
                except TimeoutError:
                    return None
                buffer += data

        return self.interface.dns_parse(buffer[2:])


class DNS_Client(object):

    def __init__(self, config):
        self.config = config
        self.doh_interface = DOH_Interface(config)
        self.tcp_interface = TCP_Interface(config)
        self.udp_interface = UDP_Interface(config)

    async def start(self):
        log(__name__).debug("Starting DNS client")
        await self.doh_interface.start()
        await self.tcp_interface.start()
        await self.udp_interface.start()

    async def stop(self):
        log(__name__).debug("Closing DNS client")
        await self.udp_interface.stop()
        await self.tcp_interface.stop()
        await self.doh_interface.stop()

    async def query(self, record: DNSRecord):
        response = await self.doh_interface.query(record)
        if self.response_ok(response):
            return response
        response = await self.udp_interface.query(record)
        if isinstance(response, DNSRecord) and response.header.tc:  # truncated
            response = await self.tcp_interface.query(record)
        return response

    @staticmethod
    def response_ok(response):
        return response is not None and response.header.rcode in [RCODE.NOERROR, RCODE.NXDOMAIN]


class Client_Interface:

    def __init__(self, config):
        self.config = config
        self.timeout = config.getfloat("peer", "timeout")
        self.next_id = 100
        self.build_ip_filter()

    def get_next_id(self):
        self.next_id = (self.next_id + 1) & 0xffff
        return self.next_id

    def mock_id(self, record):
        orig_id = record.header.id
        record_id = self.get_next_id()
        record.header.id = record_id
        request = record.pack()
        record.header.id = orig_id
        return request, record_id

    def build_ip_filter(self):
        self.ip_filter_networks = []
        if self.config.has_option("ip_filter", "ranges"):
            for net in self.config.getlist("ip_filter", "ranges"):
                self.ip_filter_networks.append(ipaddress.ip_network(net))

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
                        log(__name__).warn("DNS rebind protection, removing %s" % a)
                        del result.rr[i]
                        break
        return result

    async def start(self):
        raise NotImplementedError()

    async def stop(self):
        raise NotImplementedError()

    async def query(self, record):
        raise NotImplementedError()


class Group_Interface(Client_Interface):

    def __init__(self, config, name, client_factory, addresses):
        super().__init__(config)
        self.name = name
        self.client_factory = client_factory
        self.addresses = addresses

    async def start(self):
        log(__name__).info("Starting %s interface", self.name)
        self.clients = [self.client_factory(self, address) for address in self.addresses]
        for client in self.clients:
            await client.start()

    async def stop(self):
        log(__name__).info("Closing %s interface", self.name)
        for client in self.clients:
            await client.stop()

    async def query(self, record: DNSRecord):
        if not self.clients:
            return None

        log(__name__).info("%s query", self.name)

        dns_req, req_id = self.prepare(record)

        jobs = [asyncio.create_task(client.query(dns_req, req_id)) for client in self.clients]
        retval = None
        start = time.time()
        finished = len(jobs) == 0
        while not finished:
            done, jobs = await asyncio.wait(jobs,
                                            timeout=self.timeout,
                                            return_when=asyncio.FIRST_COMPLETED)
            finished = start + self.timeout < time.time() or len(jobs) == 0
            for job in done:
                retval = job.result()
                if isinstance(retval, DNSRecord):
                    retval.header.id = record.header.id
                if DNS_Client.response_ok(retval):
                    finished = True
                    break

        for job in jobs:
            job.cancel()
        self.cleanup(req_id)

        return retval


class UDP_Interface(Group_Interface):

    def __init__(self, config):
        super().__init__(config, "UDP", UDP_Client, config.getlist("peer", "addresses"))

    def prepare(self, record):
        return self.mock_id(record)

    def cleanup(self, req_id):
        for client in self.clients:
            client.deregister(req_id)


class TCP_Interface(Group_Interface):

    def __init__(self, config):
        super().__init__(config, "TCP", TCP_Client, config.getlist("peer", "addresses"))

    def prepare(self, record):
        return self.mock_id(record)

    def cleanup(self, req_id):
        pass


class DOH_Interface(Group_Interface):

    def __init__(self, config):
        super().__init__(config, "DOH", DOH_Client, config.getlist("peer", "doh_addresses"))

    def prepare(self, record):
        orig_id = record.header.id
        record.header.id = 0
        request = record.pack()
        record.header.id = orig_id
        dns_req = base64.urlsafe_b64encode(request).decode("ascii").rstrip("=")
        return dns_req, 0

    def cleanup(self, req_id):
        pass
