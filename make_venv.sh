#!/bin/bash

ENV=mock_dns_env

[ -d $ENV ] || python3 -m venv $ENV

. ${ENV}/bin/activate

pip install -U -r requirements.txt



