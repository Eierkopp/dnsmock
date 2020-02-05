#!/bin/bash

FNAME=/etc/dnsmock/yoyo_org_blocklist

echo A AAAA MX SOA CNAME ANY > $FNAME

curl "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts;showintro=0" | grep  "127.0.0.1 " | awk '{ print "*."$2 }' >> $FNAME
