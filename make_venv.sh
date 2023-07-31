#!/bin/bash

set -e

ENV=dnsmock_env
PYTHON=$(command -v python3)

cd "$(dirname "$0")"

rm -rf dnsmock/site-packages

[ -d "$ENV" ] || virtualenv --system-site-packages -p "$PYTHON" "$ENV"

# $ENV/bin/pip install -U -r requirements.txt

SD=$(ls -d $ENV/lib/python*/site-packages)
TD=dnsmock/env

[ -d "$SD" ] || exit 1

echo Installing from "$SD"

[ -d $TD ] && rm -rf $TD
mkdir -p $TD

for i in $SD/aiosocketpool $SD/isc_dhcp_leases $SD/re2.cpython-311-x86_64-linux-gnu.so $SD/python_hosts; do
    cp -r "$i" $TD
done
