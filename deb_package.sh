#!/bin/bash

ENV_DIR=mock_dns_env
PYTHON=`which python3.7`

[ -d $ENV_DIR ] && rm -rf $ENV_DIR

virtualenv -p $PYTHON $ENV_DIR

$ENV_DIR/bin/pip install -U -r requirements.txt

rm mock_dns.exe

dpkg-buildpackage -b --no-sign

