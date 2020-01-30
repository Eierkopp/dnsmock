#!/bin/bash

. dnsmock_env/bin/activate

python ./dnsmock --config config/devel.conf "$@"
