#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
import aiohttp
from aiosocketpool import AsyncConnectionPool, AsyncTcpConnector
import argparse
import asyncio
import base64
from dnslib import DNSRecord, QTYPE, RCODE
import ipaddress
import re
import shlex
import socket
import struct
import time
from typing import cast, Dict, List, Optional, Tuple, Type

from dnsmock.mocks import as_regex
from dnsmock.logger import log, log_exception


class DNS_Client_Base(ABC):
    def __init__(self, interface: "Group_Interface", server: str) -> None:
        self.interface = interface
        self.server = server

    @abstractmethod
    async def start(self) -> None:
        pass

    @abstractmethod
    async def stop(self) -> None:
        pass

    @abstractmethod
    async def query(self, record: DNSRecord, req_id: int) -> DNSRecord:
        pass


class DOH_Client(DNS_Client_Base):
    def __init__(self, interface: "Group_Interface", server: str) -> None:
        super().__init__(interface, server)

    async def start(self) -> None:
        log(__name__).info("Starting DOH client for address %s", self.server)
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.interface.timeout),
            headers={"Content-type": "application/dns-message"},
        )

    async def stop(self) -> None:
        log(__name__).info("Closing DOH client for %s", self.server)
        await self.session.close()

    @log_exception
    async def query(self, dns_packet: bytes, req_id: int) -> DNSRecord:
        log(__name__).info("DOH query against %s", self.server)
        async with self.session.get(self.server, params={"dns": dns_packet}) as response:
            if response.status > 299:
                return None
            if response.headers["content-type"] != "application/dns-message":
                return None

            resp = self.interface.dns_parse(await response.read())
            return resp


class UDP_Client(DNS_Client_Base, asyncio.DatagramProtocol):
    def __init__(self, interface: "Group_Interface", server: str) -> None:
        super().__init__(interface, server)
        self.requests: Dict[int, asyncio.futures.Future] = dict()

    async def start(self) -> None:
        log(__name__).info("Starting UDP client for address %s", self.server)
        loop = asyncio.get_event_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            self, family=socket.AF_INET, remote_addr=(self.server, 53)
        )

    async def stop(self) -> None:
        log(__name__).info("Closing UDP client for address %s", self.server)
        self.transport.close()

    def __call__(self) -> "UDP_Client":
        return self  # Protocol factory will always return this instance

    def datagram_received(self, data: bytes, address: Tuple[str, int]) -> None:
        resp = self.interface.dns_parse(data)
        req_id = resp.header.id
        future = self.requests.pop(req_id, None)
        if future is not None:
            future.set_result(resp)

    def deregister(self, req_id: int) -> None:
        self.requests.pop(req_id, None)

    @log_exception
    async def query(self, record: DNSRecord, req_id: int) -> bytes:
        future: asyncio.futures.Future[bytes] = asyncio.futures.Future()
        self.requests[req_id] = future
        self.transport.sendto(record)
        await future
        return future.result()


class TCP_Client(DNS_Client_Base):
    def __init__(self, interface: "Group_Interface", server: str) -> None:
        super().__init__(interface, server)
        self.pool = AsyncConnectionPool(
            factory=AsyncTcpConnector,
            reap_connections=True,
            max_lifetime=10,
            max_size=2,
        )

    async def start(self) -> None:
        log(__name__).info("Starting TCP client for address %s", self.server)

    async def stop(self) -> None:
        log(__name__).info("Closing TCP client for address %s", self.server)
        self.pool.reap_all()
        self.pool.stop_reaper()

    def is_complete(self, buffer: bytes) -> bool:
        if len(buffer) < 2:
            return False
        return cast(int, struct.unpack(">h", buffer[:2])[0] + 2) <= len(buffer)

    @log_exception
    async def query(self, record: bytes, req_id: int) -> DNSRecord:
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
    def __init__(self, config: argparse.Namespace) -> None:
        self.config = config
        self.doh_interface = DOH_Interface(config)
        self.tcp_interface = TCP_Interface(config)
        self.udp_interface = UDP_Interface(config)

    async def start(self) -> None:
        log(__name__).debug("Starting DNS client")
        await self.doh_interface.start()
        await self.tcp_interface.start()
        await self.udp_interface.start()

    async def stop(self) -> None:
        log(__name__).debug("Closing DNS client")
        await self.udp_interface.stop()
        await self.tcp_interface.stop()
        await self.doh_interface.stop()

    async def query(self, record: bytes) -> DNSRecord:
        response = await self.doh_interface.query(record)
        if self.response_ok(response):
            return response
        response = await self.udp_interface.query(record)
        if isinstance(response, DNSRecord) and response.header.tc:  # truncated
            response = await self.tcp_interface.query(record)
        return response

    @staticmethod
    def response_ok(response: DNSRecord) -> bool:
        return response is not None and response.header.rcode in [
            RCODE.NOERROR,
            RCODE.NXDOMAIN,
        ]


class Client_Interface(ABC):
    def __init__(self, config: argparse.Namespace) -> None:
        self.config = config
        self.timeout = config.peer_timeout
        self.next_id = 100
        self.build_ip_filter()

    def get_next_id(self) -> int:
        self.next_id = (self.next_id + 1) & 0xFFFF
        return self.next_id

    def mock_id(self, record: DNSRecord) -> Tuple[DNSRecord, int]:
        orig_id = record.header.id
        record_id = self.get_next_id()
        record.header.id = record_id
        request = record.pack()
        record.header.id = orig_id
        return request, record_id

    def build_ip_filter(self) -> None:
        self.ip_filter_networks = []
        for net in self.config.ip_filter_ranges:
            self.ip_filter_networks.append(ipaddress.ip_network(net))

    def dns_parse(self, record: bytes) -> DNSRecord:
        """Parse a dns response and for A/AAAA
        records filter out matching resource records"""
        result = DNSRecord.parse(record)
        if result.header.rcode != 0:  # NOERROR
            return result

        num = len(result.rr)
        for i in range(num - 1, -1, -1):
            r = result.rr[i]
            if QTYPE[r.rtype] in ["A", "AAAA"]:
                a = ipaddress.ip_address(r.rdata)
                for n in self.ip_filter_networks:
                    if a in n:
                        log(__name__).warn("DNS rebind protection, removing %s" % a)
                        del result.rr[i]
                        break
        return result

    @abstractmethod
    async def start(self) -> None:
        pass

    @abstractmethod
    async def stop(self) -> None:
        pass

    @abstractmethod
    async def query(self, record: DNSRecord) -> Optional[DNSRecord]:
        pass

    @abstractmethod
    def prepare(self, record: DNSRecord) -> Tuple[DNSRecord, int]:
        pass

    @abstractmethod
    def cleanup(self, req_id: int) -> None:
        pass


class Group_Interface(Client_Interface):
    def __init__(
        self,
        config: argparse.Namespace,
        name: str,
        client_factory: Type[DNS_Client_Base],
        peers: List[str],
    ) -> None:
        super().__init__(config)
        self.name = name
        self.client_factory = client_factory
        self.peers = peers
        self.masks: List[Tuple[str, re.Pattern]] = list()
        self.clients: Dict[str, List[DNS_Client_Base]] = dict()

    async def start(self) -> None:
        log(__name__).info("Starting %s interface", self.name)
        for peer_list in self.peers:
            fields = [x.strip() for x in shlex.split(peer_list)]
            mask = fields[0]
            self.masks.append((mask, as_regex(mask)))
            self.clients[mask] = [self.client_factory(self, address) for address in fields[1:]]
            for client in self.clients[mask]:
                await client.start()

    async def stop(self) -> None:
        log(__name__).info("Closing %s interface", self.name)
        for clients in self.clients.values():
            for client in clients:
                await client.stop()

    async def query(self, record: DNSRecord) -> Optional[DNSRecord]:
        if not self.clients:
            return None

        dns_req, req_id = self.prepare(record)
        jobs = set()
        for mask, mask_expr in self.masks:
            if mask_expr.match(str(record.q.qname)):
                log(__name__).info(
                    "Mask %s matches %s for %s query", mask, record.q.qname, self.name
                )
                clients = self.clients[mask]
                for client in clients:
                    jobs.add(asyncio.create_task(client.query(dns_req, req_id)))
                break

        retval = None
        start = time.time()
        finished = len(jobs) == 0
        while not finished:
            done, jobs = await asyncio.wait(
                jobs, timeout=self.timeout, return_when=asyncio.FIRST_COMPLETED
            )
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
    def __init__(self, config: argparse.Namespace) -> None:
        super().__init__(config, "UDP", UDP_Client, config.peer_addresses)

    def prepare(self, record: bytes) -> Tuple[DNSRecord, int]:
        return self.mock_id(record)

    def cleanup(self, req_id: int) -> None:
        for mask, _ in self.masks:
            for client in self.clients[mask]:
                cast(UDP_Client, client).deregister(req_id)


class TCP_Interface(Group_Interface):
    def __init__(self, config: argparse.Namespace) -> None:
        super().__init__(config, "TCP", TCP_Client, config.peer_addresses)

    def prepare(self, record: bytes) -> Tuple[DNSRecord, int]:
        return self.mock_id(record)

    def cleanup(self, req_id: int) -> None:
        pass


class DOH_Interface(Group_Interface):
    def __init__(self, config: argparse.Namespace) -> None:
        super().__init__(config, "DOH", DOH_Client, config.peer_doh_addresses)

    def prepare(self, record: DNSRecord) -> Tuple[DNSRecord, int]:
        orig_id = record.header.id
        record.header.id = 0
        request = record.pack()
        record.header.id = orig_id
        dns_req = base64.urlsafe_b64encode(request).decode("ascii").rstrip("=")
        return dns_req, 0

    def cleanup(self, req_id: int) -> None:
        pass
