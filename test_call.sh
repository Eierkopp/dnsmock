#!/bin/bash

#dig @127.0.0.1 -p 5359 +tcp www.google.com anton.my.domain.name
#dig @127.0.0.1 -p 5359 www.google.com RRSIG
#dig @127.0.0.1 -p 5359 www.facebook.com

#dig @127.0.0.1 -p 5359 +tcp _sip._tcp.my.domain.name SRV
# dig @127.0.0.1 -p 5359 +tcp _http._tcp.gateway SRV
# dig @127.0.0.1 -p 5359 120.61.96.156.in-addr.arpa PTR
# dig @127.0.0.1 -p 5359 20.178.168.192.in-addr.arpa PTR
dig @192.168.178.21 -p 5359 www.google.com A
# dig @127.0.0.1 -p 5359 +tcp www.google.com A
#dig @127.0.0.1 -p 5359 +tcp test.domain A
# dig @127.0.0.1 -p 5359 +tcp test.domain2 CNAME
#dig @127.0.0.1 -p 5359 +tcp test.domain3 AAAA
#dig @127.0.0.1 -p 5359 +tcp test.domain4 A

#dig @127.0.0.1 -p 5359 +tcp  A

#dig @127.0.0.1 -p 5359 +tcp test.host TXT

#dig @127.0.0.1 -p 5359 current.cvd.clamav.net TXT

# dig @127.0.0.1 -p 5359 ip6-allnodes AAAA
#dig @127.0.0.1 +tcp -p 5359 ip6-allnodes AAAA

# overwrite cache entry:

# temporarily set some SRV record
# curl -vd '[20, 10, 5060, "some.domain"]' -H "Content-Type: application/json" http://localhost:6668/set/SRV/test.domain4
# dig @127.0.0.1 -p 5359 +tcp test.domain4 SRV





# curl -i http://localhost:6668/flush

# curl -i http://localhost:6668/update


# Tests for blocklist_local_MX

# dig @127.0.0.1 -p 5359 test MX
# dig @127.0.0.1 -p 5359 xxx.anton MX
# dig @127.0.0.1 -p 5359 xxx.my.domain.name MX

# Tests for blocklist_local_TXT

# dig @127.0.0.1 -p 5359 test TXT
# dig @127.0.0.1 -p 5359 current.cvd.clamav.net TXT


