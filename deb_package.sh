#!/bin/bash

ENV_DIR=dnsmock_env

./make_venv.sh

find . -name "__pycache__" -type d -exec rm -rf {} \;

dpkg-buildpackage -b --no-sign

dpkg-deb -c ../dnsmock*.deb
