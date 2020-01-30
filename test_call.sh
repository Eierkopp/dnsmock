#!/bin/bash

dig @127.0.0.1 -p 5353 +tcp www.google.com www.opendns.com
dig @127.0.0.1 -p 5353 www.facebook.com

#dig @127.0.0.1 -p 5353 +tcp _sip._tcp.eier.kopp SRV

