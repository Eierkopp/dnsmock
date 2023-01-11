#!/bin/bash

ENV_DIR=dnsmock_env

./make_venv.sh

find . -name "__pycache__" -type d -exec rm -rf {} \;

dpkg-buildpackage -b --no-sign

VERSION=`dpkg-parsechangelog -S Version`

dpkg-deb -c ../dnsmock_${VERSION}_amd64.deb
