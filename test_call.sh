#!/bin/bash

#dig @127.0.0.1 -p 5353 +tcp www.google.com www.opendns.com
#dig @127.0.0.1 -p 5353 www.facebook.com

dig @127.0.0.1 -p 5353 +tcp _sip._tcp.my.domain.name SRV

#dig @127.0.0.1 -p 5353 +tcp test.domain A
#dig @127.0.0.1 -p 5353 +tcp test.domain2 CNAME
#dig @127.0.0.1 -p 5353 +tcp test.domain3 AAAA

