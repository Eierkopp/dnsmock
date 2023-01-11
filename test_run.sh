#!/bin/bash

# . dnsmock_env/bin/activate
PYTHON_PATH=`pwd`
python3 bin/dnsmock --config config/devel.conf "$@"
