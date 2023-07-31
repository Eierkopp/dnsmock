#!/bin/bash

export PYTHONPATH
PYTHONPATH="$(dirname "$0")":"$(dirname "$0")"/dnsmock

export DNSMOCK_CONFIG
DNSMOCK_CONFIG=config/config.yaml

python3 bin/dnsmock "$@"
