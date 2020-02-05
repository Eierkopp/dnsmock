#!/usr/bin/env python3

import json
import re
import socket
from python_hosts.hosts import Hosts
import cachetools
import logging
from collections import OrderedDict
from isc_dhcp_leases import IscDhcpLeases
from dnslib import DNSRecord, QTYPE, RR, RDMAP, RCODE

from dnsmocklib.file_guard import Guard

logging.basicConfig(level=logging.DEBUG)

MOCKED_RECORD_TYPES = ["A", "PTR", "AAAA", "MX", "SOA", "CNAME", "SRV", "NAPTR", "ANY"]


def qt_qn(record):
    return QTYPE[record.q.qtype], str(record.q.qname).rstrip(".")


class Cache:

    def __init__(self, config):
        self.config = config
        self.ttl_cache = cachetools.TTLCache(config.getint("cache", "size"),
                                             config.getint("cache", "ttl"))
        logging.getLogger(__name__).info("Cache initialized")

    def add(self, query, response):
        qtype, qname = qt_qn(query)
        logging.getLogger(__name__).info("Caching response for %s: %s" % (qtype, qname))
        self.ttl_cache[(qtype, qname)] = response

    def forget(self, hostname=None):
        if hostname is not None:
            logging.getLogger(__name__).info("Host %s removed from cache", hostname)
            for qt in MOCKED_RECORD_TYPES:
                self.ttl_cache.pop((qt, hostname), None)
        else:
            logging.getLogger(__name__).info("Cache flushed")
            self.ttl_cache.clear()

    def get(self, entry):
        return self.ttl_cache.get(entry)


class MockHolder:

    def __init__(self, config):
        self.config = config
        self.active = None
        self.standby = None
        self.cache = Cache(config)
        self.guard = Guard(config.getint("local", "refresh_after"), self.build_mocks)
        self.build_mocks()
        self.guard.start()

    def resolve(self, record, addr):
        if self.standby is not None:
            logging.getLogger(__name__).info("Activating new mock table")
            self.active, self.standby = self.standby, None
            self.cache.forget()

        qtype, qname = qt_qn(record)
        logging.getLogger(__name__).info("Resolving %s: %s for %s" % (qtype, qname, addr))

        response = self.cache.get((qtype, qname))
        if response:  # already in cache
            logging.getLogger(__name__).info("Returning cached response for %s: %s", qtype, qname)
            response.header.id = record.header.id
            return response.pack()

        if qtype not in MOCKED_RECORD_TYPES:  # not a mocked qtype
            logging.getLogger(__name__).info("Not a mocked query type: %s" % qtype)
            return None

        response = record.reply()

        result = self.mock_record(qtype, qname)

        if result is None:  # not mocked
            return None
        else:
            fnames, results = result
            logging.getLogger(__name__).info("Matching %s -> mocked response %s",
                                             fnames, list(results))
            for qt, qt_result in results:
                self.add_record(qt, response, qname, qt_result)
            if len(response.rr) == 0:
                response.header.rcode = RCODE.NXDOMAIN
                logging.getLogger(__name__).info("Returning empty response for %s: %s",
                                                 qtype, qname)
            return response.pack()

    def mock_record(self, qtype, qname):
        mocked = False
        filenames = set()
        mocks = set()
        for expr, replacements in self.active.items():
            m = expr.fullmatch(qname)
            if not m or qtype not in replacements:
                continue
            mocked = True
            mocks.update(replacements[qtype])
            filenames.update(replacements["fname"])
        if mocked:
            return filenames, mocks
        else:
            return None

    def filter_response(self, record):
        if not isinstance(record, DNSRecord):
            return

        rrs = record.rr
        record.rr = []
        already_mocked = set()
        for rr in rrs:
            rtype = QTYPE[rr.rtype]
            rname = str(rr.rname)
            r = self.mock_record(rtype, rname)
            if r is None:  # not mocked
                record.add_answer(rr)
            else:
                if (rtype, rname) not in already_mocked:
                    already_mocked.add((rtype, rname))
                    fnames, mocks = r
                    logging.getLogger(__name__).info("Filtering %s: %s. %s -> mocked response %s",
                                                     rtype, rname, fnames, list(mocks))
                    for qt, qt_result in mocks:
                        self.add_record(qt, record, rname, qt_result)

    @staticmethod
    def add_record(qt_name, response, qname, value):
        qt = QTYPE.reverse[qt_name]
        if isinstance(value, tuple):
            response.add_answer(RR(qname, qt, rdata=RDMAP[qt_name](*value)))
        else:
            response.add_answer(RR(qname, qt, rdata=RDMAP[qt_name](value)))

    def build_mocks(self):
        mock = {x: OrderedDict() for x in MOCKED_RECORD_TYPES}
        if self.config.has_option("hosts", "files"):
            for fname in self.config.getlist("hosts", "files"):
                self.add_hosts(fname, mock)
                self.guard.add_file(fname)

        if self.config.has_option("isc_dhcp", "leases_v4"):
            for fname in self.config.getlist("isc_dhcp", "leases_v4"):
                self.add_leases(fname, mock)
                self.guard.add_file(fname)

        if self.config.has_option("isc_dhcpd", "files"):
            for fname in self.config.getlist("isc_dhcpd", "files"):
                self.add_isc_dhcpd(fname, mock)
                self.guard.add_file(fname)

        if self.config.has_option("blocklist", "files"):
            for fname in self.config.getlist("blocklist", "files"):
                self.add_blockfile(fname, mock)
                self.guard.add_file(fname)

        self.standby = self.build_regex(mock)

    def set_defaults(self, fname, mock, name, records=MOCKED_RECORD_TYPES):
        entry = mock.setdefault(name, dict(fname=set()))
        entry["fname"].add(fname)
        for i in records:
            entry.setdefault(i, set())

    def add_hosts(self, fname, mock):
        """For host entries all record types are mocked"""

        h = Hosts(fname)
        for e in h.entries:
            if not e.names:
                continue
            for n in e.names:
                if e.entry_type == "ipv4":
                    self.set_defaults(fname, mock, n)
                    ptr_addr = self.to_ptr_v4(e.address)
                    self.set_defaults(fname, mock, ptr_addr)
                    mock[n]["A"].add(("A", e.address))
                    mock[n]["ANY"].add(("A", e.address))
                    mock[ptr_addr]["PTR"].add(("PTR", n))
                    mock[ptr_addr]["ANY"].add(("PTR", n))
                elif e.entry_type == "ipv6":
                    self.set_defaults(fname, mock, n)
                    ptr_addr = self.to_ptr_v6(e.address)
                    self.set_defaults(fname, mock, ptr_addr)
                    mock[n]["A"].add(("A", e.address))
                    mock[n]["ANY"].add(("A", e.address))
                    mock[ptr_addr]["PTR"].add(("PTR", n))
                    mock[ptr_addr]["ANY"].add(("PTR", n))

    def add_leases(self, fname, mock):
        leases = IscDhcpLeases(fname)
        for l in leases.get_current().values():
            self.set_defaults(fname, mock, l.hostname)
            ptr_addr = self.to_ptr_v4(l.ip)
            self.set_defaults(fname, mock, ptr_addr)
            mock[l.hostname]["A"].add(("A", l.ip))
            mock[l.hostname]["ANY"].add(("A", l.ip))
            mock[ptr_addr]["PTR"].add(("PTR", l.hostname))
            mock[ptr_addr]["ANY"].add(("PTR", l.hostname))
            fqdn = l.hostname + "." + self.config.get("local", "my_domain")
            self.set_defaults(fname, mock, fqdn)
            mock[fqdn]["A"].add(("A", l.ip))
            mock[fqdn]["ANY"].add(("A", l.ip))
            mock[ptr_addr]["PTR"].add(("PTR", fqdn))
            mock[ptr_addr]["ANY"].add(("PTR", fqdn))

    def add_isc_dhcpd(self, fname, mock):
        host_expr = re.compile(r"(?:^|\s)host\s+([^\s]*)\s+\{[^\}]*fixed-address\s+([0-9\.]+).*?\}",
                               re.DOTALL | re.MULTILINE | re.I)

        with open(fname) as f:
            data = f.read()
            for m in host_expr.finditer(data):
                n, ip = m.group(1), m.group(2)
                self.set_defaults(fname, mock, n)
                ptr_addr = self.to_ptr_v4(ip)
                self.set_defaults(fname, mock, ptr_addr)
                mock[n]["A"].add(("A", ip))
                mock[n]["ANY"].add(("A", ip))
                mock[ptr_addr]["PTR"].add(("PTR", n))
                mock[ptr_addr]["ANY"].add(("PTR", n))
                fqdn = n + "." + self.config.get("local", "my_domain")
                self.set_defaults(fname, mock, fqdn)
                mock[fqdn]["A"].add(("A", ip))
                mock[fqdn]["ANY"].add(("A", ip))
                mock[ptr_addr]["PTR"].add(("PTR", fqdn))
                mock[ptr_addr]["ANY"].add(("PTR", fqdn))

    def add_blockfile(self, fname, mock):
        """Blockfiles apply to all record types listed in the first line of
        the blockfile. For those record types an empty response is added"""
        with open(fname) as f:
            qtypes = f.readline().strip().upper().split()
            for line in f.readlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) == 1:
                    self.set_defaults(fname, mock, line, qtypes)
                else:
                    mocked_result = json.loads(parts[1])
                    self.set_mocks(fname, mock, parts[0], mocked_result, qtypes)

    def as_regex(self, key):
        """convert blocklist pattern to Python regex
        + matches a section, e.g. x.+.y matches x.eier.y but not x.eier.y.z
        * matches everything, e.g. *x.y matches a.x.y or ax.y
        *. matches everything even without the dot, e.g. *.x.y matches x.y or a.b.x.y
        """

        e = key.replace(".", r"\.")
        e = e.replace("*", ".*")
        e = e.replace(r".*\.", r"(?:.*\.)?")
        e = e.replace("+", r"[^\.]*")
        return re.compile(e, re.I)

    def build_regex(self, mock):
        retval = OrderedDict()
        for key, mocks in mock.items():
            key = self.as_regex(key)
            retval[key] = mocks
        return retval

    def set_mocks(self, fname, mock, name, mocks, records=MOCKED_RECORD_TYPES):
        entry = mock.setdefault(name, dict(fname=set()))
        entry["fname"].add(fname)
        for i in records:
            entry.setdefault(i, set())
            for record_type, values in mocks.items():
                for v in values:
                    entry[i].add((record_type, tuple(v)))

    def to_ptr_v4(self, address):
        bytes = socket.inet_pton(socket.AF_INET, address)
        result = ""
        for b in bytes[::-1]:
            result += "%d." % b
        return result + "in-addr.arpa"

    def to_ptr_v6(self, address):
        bytes = socket.inet_pton(socket.AF_INET6, address)
        result = ""
        for b in bytes[::-1]:
            result += "%x.%x." % (b & 0xf, b >> 4)
        return result + "ip6.arpa"

    def stop(self):
        self.guard.stop()


class Context:

    def __init__(self, config, loop):
        self.config = config

    def start(self):
        self.mocks = MockHolder(self.config)
        self.cache = self.mocks.cache

    def stop(self):
        self.mocks.stop()
