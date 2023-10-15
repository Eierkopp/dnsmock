#!/usr/bin/env python3

import argparse
import json
from pprint import pformat
import socket
from python_hosts.hosts import Hosts
import cachetools

from isc_dhcp_leases import IscDhcpLeases
from dnslib import DNSRecord, QTYPE, RR, RDMAP, RCODE
from typing import cast, Dict, Generator, List, Optional, Set, Tuple

from dnsmock.logger import log
from dnsmock.file_guard import Guard
from dnsmock.leakybucket import LeakyBucket


try:
    import re2 as re

    log(__name__).info("Using re2 regexp library")
except ImportError:
    log(__name__).warning("Falling back to re module, consider installing pyre2")
    import re


MOCKED_RECORD_TYPES = [
    "A",
    "PTR",
    "AAAA",
    "MX",
    "SOA",
    "CNAME",
    "SRV",
    "NAPTR",
    "TXT",
    "ANY",
]


def qt_qn(record: DNSRecord) -> Tuple[str, str]:
    return QTYPE[record.q.qtype], str(record.q.qname).rstrip(".")


def as_regex(key: str) -> re.Pattern:
    """convert blocklist pattern to Python regex
    + matches a section, e.g. x.+.y matches x.eier.y but not x.eier.y.z
    * matches everything, e.g. *x.y matches a.x.y or ax.y
    *. matches everything even without the dot, e.g. *.x.y matches x.y or a.b.x.y but not ax.y
    """

    e = key.replace(".", r"\.")
    e = e.replace("*", ".*")
    e = e.replace(r".*\.", r"(?:.*\.)?")
    e = e.replace("+", r"[^\.]*")
    return re.compile(e, re.I)


class Cache:
    def __init__(self, config: argparse.Namespace) -> None:
        self.config = config
        self.ttl_cache: cachetools.Cache = cachetools.TTLCache(config.cache_size, config.cache_ttl)
        log(__name__).info("Cache initialized")

    def add(self, query: DNSRecord, response: DNSRecord, bucket: LeakyBucket) -> None:
        qtype, qname = qt_qn(query)
        log(__name__).info("Caching response for %s: %s" % (qtype, qname))
        self.ttl_cache[(qtype, qname)] = (response, bucket)

    def forget(self, hostname: Optional[str] = None) -> None:
        if hostname is not None:
            log(__name__).info("Host %s removed from cache", hostname)
            for qt in MOCKED_RECORD_TYPES:
                self.ttl_cache.pop((qt, hostname), None)
        else:
            log(__name__).info("Cache flushed")
            self.ttl_cache.clear()

    def get(self, entry: Tuple[str, str]) -> Optional[Tuple[DNSRecord, LeakyBucket]]:
        return self.ttl_cache.get(entry)


class Replacement:
    def __init__(self) -> None:
        # a replacement for a record type is a None or a json-encoded list of list(s) or dict(s)
        # holding the parameters for dnslib's RD derived constructors.
        self.replacements: Dict[str, Optional[Set[str]]] = dict()

    def add(self, record_type: str, value: Optional[str]) -> None:
        if value is None:
            self.replacements[record_type] = None
            return
        try:
            dec_tmp = json.loads(value)
            if not isinstance(dec_tmp, list):
                value = f'[["{value}"]]'
        except json.decoder.JSONDecodeError:  # probably a plain string
            value = f'[["{value}"]]'
        v = self.replacements.setdefault(record_type, set())
        if v is not None:
            v.add(value)

    def as_list(self, qtype: str) -> Generator[Tuple[str, str], None, None]:
        for rt, values in self.replacements.items():
            if values is not None:
                for value in values:
                    yield rt, value

    def is_whitelisted(self, qtype: str) -> bool:
        return self.replacements.get(qtype, 0) is None

    def __str__(self) -> str:
        rv = ""
        for rt in MOCKED_RECORD_TYPES:
            if rt in self.replacements:
                rp = self.replacements[rt]
                rv += f"{rt:4}:"
                if rp is None:
                    rv += "WHITELISTED"
                else:
                    rv += ", ".join(rp)
        return rv


class Mock:
    def __init__(self, mask: str) -> None:
        self.mask = as_regex(mask)
        self.fnames: Set[str] = set()
        self.mocked = Replacement()

    def get(self) -> Replacement:
        return self.mocked

    def add(self, fname: str, record_type: str, value: Optional[str] = None) -> None:
        self.fnames.add(fname)
        self.mocked.add(record_type, value)

    def block(self, fname: str, record_types: List[str]) -> None:
        self.fnames.add(fname)
        for rt in record_types:
            self.mocked.add(rt, "[]")

    def __repr__(self) -> str:
        return f"{self.mask.pattern} ({self.fnames}) -> {self.mocked}"

    def __str__(self) -> str:
        return f"{self.mask.pattern} ({self.fnames}) -> {self.mocked}"


TEMP_MOCKS_DICT = Dict[str, Dict[str, Mock]]
MOCKS_DICT = Dict[str, List[Mock]]


class MockHolder:
    class DropException(Exception):
        pass

    def __init__(self, config: argparse.Namespace) -> None:
        self.config = config
        self.cache = Cache(config)
        self.active: MOCKS_DICT = dict()
        self.standby: Optional[MOCKS_DICT] = None
        self.guard = Guard(config.local_refresh_after, self.build_mocks)
        self.build_mocks()
        self.guard.start()

    def handle_updates(self) -> None:
        if self.standby is not None:
            log(__name__).info("Activating new mock table")
            self.active, self.standby = self.standby, None
            self.cache.forget()

    def resolve(self, record: DNSRecord, addr: Tuple[str, int]) -> Optional[bytes]:
        self.handle_updates()

        qtype, qname = qt_qn(record)
        log(__name__).info("Resolving %s: %s for %s" % (qtype, qname, addr))

        cache_entry = self.cache.get((qtype, qname))
        if cache_entry:  # already in cache
            response, bucket = cache_entry
            if bucket.try_add():
                log(__name__).info("Returning cached response for %s: %s", qtype, qname)
                response.header.id = record.header.id
                return cast(bytes, response.pack())
            else:
                log(__name__).info("DOS protection, dropping request %s: %s", qtype, qname)
                raise MockHolder.DropException("not mocked")

        if qtype not in MOCKED_RECORD_TYPES:  # not a mocked qtype
            log(__name__).info("Not a mocked query type: %s" % qtype)
            raise MockHolder.DropException("not mocked")

        response = record.reply()

        result = self.mock_record(qtype, qname)
        if result is None:  # not mocked
            return None
        else:
            fnames, mocks = result
            log(__name__).info("Matching %s -> mocked response %s", fnames, pformat(mocks))
            for rt, value in mocks:
                self.add_record(qname, response, rt, value)
            if len(response.rr) == 0:
                response.header.rcode = RCODE.NXDOMAIN
                log(__name__).info("Returning empty response for %s: %s", qtype, qname)
            return cast(bytes, response.pack())

    def mock_record(
        self, qtype: str, qname: str
    ) -> Optional[Tuple[Set[str], Set[Tuple[str, str]]]]:
        mocked = False
        filenames = set()
        mocks: Set[Tuple[str, str]] = set()
        for mock in self.active.get(qtype, list()):
            m = mock.mask.fullmatch(qname)
            if not m:
                continue
            replacement = mock.get()
            if replacement.is_whitelisted(qtype):
                return None
            mocked = True
            mocks.update(replacement.as_list(qtype))
            filenames.update(mock.fnames)
        if mocked:
            return filenames, mocks
        else:
            return None

    def filter_response(self, record: DNSRecord) -> DNSRecord:
        if not isinstance(record, DNSRecord):
            return

        rrs = record.rr
        record.rr = []
        already_mocked = set()
        for rr in rrs:
            rtype = QTYPE[rr.rtype]
            rname = str(rr.rname).rstrip(".")
            r = self.mock_record(rtype, rname)
            if r is None:  # not mocked
                record.add_answer(rr)
            else:
                if (rtype, rname) not in already_mocked:
                    already_mocked.add((rtype, rname))
                    fnames, mocks = r
                    log(__name__).info(
                        "Filtering %s: %s. %s -> mocked response %s",
                        rtype,
                        rname,
                        fnames,
                        list(mocks),
                    )
                    for qt, qt_result in mocks:
                        self.add_record(rname, record, rtype, qt_result)

    @staticmethod
    def add_record(qt_name: str, response: DNSRecord, qtype: str, value: list | dict | str) -> None:
        qt = QTYPE.reverse[qtype]
        if isinstance(value, list):
            response.add_answer(RR(qt_name, qt, rdata=RDMAP[qtype](*value)))
        elif isinstance(value, dict):
            response.add_answer(RR(qt_name, qt, rdata=RDMAP[qtype](**value)))
        else:  # encoded string
            values = json.loads(value)
            for data in values:
                MockHolder.add_record(qt_name, response, qtype, data)

    def build_mocks(self) -> None:
        temp_mocks: TEMP_MOCKS_DICT = dict()
        for fname in self.config.hosts_files:
            self.add_hosts(fname, temp_mocks)
            self.guard.add_file(fname)

        for fname in self.config.isc_dhcpd_leases_v4:
            self.add_leases(fname, temp_mocks)
            self.guard.add_file(fname)

        for fname in self.config.isc_dhcpd_files:
            self.add_isc_dhcpd(fname, temp_mocks)
            self.guard.add_file(fname)

        for fname in self.config.blocklist_files:
            self.add_blockfile(fname, temp_mocks)
            self.guard.add_file(fname)

        mocks: MOCKS_DICT = dict()
        for rt in MOCKED_RECORD_TYPES:
            mocked = temp_mocks.get(rt, dict())
            mocks[rt] = list()
            for mask, mock in mocked.items():
                log(__name__).debug("%s:%s", rt, mock)
                mocks[rt].append(mock)
        self.standby = mocks

    def set_defaults(self, mocks: TEMP_MOCKS_DICT, record_type: str, mask: str) -> Mock:
        return mocks.setdefault(record_type, dict()).setdefault(mask, Mock(mask))

    def add_hosts(self, fname: str, mocks: TEMP_MOCKS_DICT) -> None:
        """For host entries all record types are mocked"""
        log(__name__).debug("Scanning %s", fname)
        h = Hosts(fname)
        for e in h.entries:
            if not e.names:
                continue
            for n in e.names:
                if e.entry_type == "ipv4":
                    self.set_defaults(mocks, "A", n).add(fname, "A", e.address)
                    self.set_defaults(mocks, "ANY", n).add(fname, "A", e.address)
                    ptr_addr = self.to_ptr_v4(e.address)
                    self.set_defaults(mocks, "ANY", ptr_addr).add(fname, "PTR", n)
                    self.set_defaults(mocks, "PTR", ptr_addr).add(fname, "PTR", n)
                elif e.entry_type == "ipv6":
                    self.set_defaults(mocks, "AAAA", n).add(fname, "AAAA", e.address)
                    self.set_defaults(mocks, "ANY", n).add(fname, "AAAA", e.address)
                    ptr_addr = self.to_ptr_v6(e.address)
                    self.set_defaults(mocks, "ANY", ptr_addr).add(fname, "PTR", n)
                    self.set_defaults(mocks, "PTR", ptr_addr).add(fname, "PTR", n)

    def add_leases(self, fname: str, mocks: TEMP_MOCKS_DICT) -> None:
        leases = IscDhcpLeases(fname)
        for lease in leases.get_current().values():
            ptr_addr = self.to_ptr_v4(lease.ip)
            self.set_defaults(mocks, "A", lease.hostname).add(fname, "A", lease.ip)
            self.set_defaults(mocks, "ANY", lease.hostname).add(fname, "A", lease.ip)
            self.set_defaults(mocks, "PTR", ptr_addr).add(fname, "PTR", lease.hostname)
            self.set_defaults(mocks, "ANY", ptr_addr).add(fname, "PTR", lease.hostname)
            fqdn = lease.hostname + "." + self.config.local_my_domain
            self.set_defaults(mocks, "A", fqdn).add(fname, "A", lease.ip)
            self.set_defaults(mocks, "ANY", fqdn).add(fname, "A", lease.ip)
            self.set_defaults(mocks, "PTR", ptr_addr).add(fname, "PTR", fqdn)
            self.set_defaults(mocks, "ANY", ptr_addr).add(fname, "PTR", fqdn)

    def add_isc_dhcpd(self, fname: str, mocks: TEMP_MOCKS_DICT) -> None:
        host_expr = re.compile(
            r"(?:^|\s)host\s+([^\s]*)\s+\{[^\}]*fixed-address\s+([0-9\.]+).*?\}",
            re.DOTALL | re.MULTILINE | re.I,
        )

        with open(fname) as f:
            data = f.read()
            for m in host_expr.finditer(data):
                n, ip = m.group(1), m.group(2)
                self.set_defaults(mocks, "A", n).add(fname, "A", ip)
                self.set_defaults(mocks, "ANY", n).add(fname, "A", ip)
                ptr_addr = self.to_ptr_v4(ip)
                self.set_defaults(mocks, "PTR", ptr_addr).add(fname, "PTR", n)
                self.set_defaults(mocks, "ANY", ptr_addr).add(fname, "PTR", n)
                fqdn = n + "." + self.config.local_my_domain
                self.set_defaults(mocks, "A", fqdn).add(fname, "A", ip)
                self.set_defaults(mocks, "ANY", fqdn).add(fname, "A", ip)
                self.set_defaults(mocks, "PTR", ptr_addr).add(fname, "PTR", fqdn)
                self.set_defaults(mocks, "ANY", ptr_addr).add(fname, "PTR", fqdn)

    def add_blockfile(self, fname: str, mocks: TEMP_MOCKS_DICT) -> None:
        """Blockfiles apply to all record types listed in the first line of
        the blockfile. For those record types an empty response is added"""

        with open(fname) as f:
            qtypes = f.readline().strip().upper().split()
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                for qtype in qtypes:
                    if len(parts) == 1:
                        self.set_defaults(mocks, qtype, line).block(fname, qtypes)
                    else:
                        if parts[1] == "WHITELISTED":
                            for rt in qtypes:
                                self.set_defaults(mocks, qtype, parts[0]).add(fname, rt)
                        else:
                            mocked_result = json.loads(parts[1])
                            for rt in qtypes:
                                if rt in mocked_result:
                                    self.set_defaults(mocks, qtype, parts[0]).add(
                                        fname, rt, json.dumps(mocked_result[rt])
                                    )

    def to_ptr_v4(self, address: str) -> str:
        bytes = socket.inet_pton(socket.AF_INET, address)
        result = ""
        for b in bytes[::-1]:
            result += "%d." % b
        return result + "in-addr.arpa"

    def to_ptr_v6(self, address: str) -> str:
        bytes = socket.inet_pton(socket.AF_INET6, address)
        result = ""
        for b in bytes[::-1]:
            result += "%x.%x." % (b & 0xF, b >> 4)
        return result + "ip6.arpa"

    def stop(self) -> None:
        self.guard.stop()


class Mocks(MockHolder):
    def __init__(self, config: argparse.Namespace) -> None:
        super().__init__(config)
        self.cache = self.cache

    def start(self) -> None:
        pass

    def stop(self) -> None:
        super().stop()
