#!/bin/bash

export PYTHONPATH="$(dirname "$0")"

python3 bin/dnsmock --config config/devel.conf "$@"
