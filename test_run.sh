#!/bin/bash

. dnsmock_env/bin/activate

python ./dnsmock.py --config config/devel.conf "$@"
