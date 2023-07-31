#!/bin/bash

set -e

cd "$(dirname "$0")"

export MYPYPATH=dnsmock

mypy bin/dnsmock dnsmock/*.py
