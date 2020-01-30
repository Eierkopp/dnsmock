#!/bin/bash

ENV_DIR=dnsmock_env
PYTHON=`which python3`

[ -d $ENV_DIR ] && rm -rf $ENV_DIR

virtualenv -p $PYTHON $ENV_DIR

$ENV_DIR/bin/pip install -U -r requirements.txt

[ -f dnsmock ] && rm dnsmock

dpkg-buildpackage -b --no-sign

