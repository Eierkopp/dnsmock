#!/bin/bash

ENV=dnsmock_env
PYTHON=`command -v python3`

cd `dirname $0`

[ -d $ENV ] && rm -rf $ENV
rm -rf dnsmock/site-packages

virtualenv --system-site-packages -p $PYTHON $ENV

$ENV/bin/pip install -U -r requirements.txt

mv $ENV/lib/python*/site-packages dnsmock
