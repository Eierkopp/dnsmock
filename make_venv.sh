#!/bin/bash

ENV=dnsmock_env

[ -d $ENV ] || python3 -m venv $ENV

. ${ENV}/bin/activate

pip install -U -r requirements.txt



