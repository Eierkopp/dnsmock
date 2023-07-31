#!/bin/bash
#
# source me !
#
# ignore sourced input files
# shellcheck source=/dev/null


cd "$(dirname "$0")" || exit 1

export TEST_CONFIG=config/config.yaml

if [ -z "$1" ]; then 
    emacs mypy.ini &
    sleep 3
    em
fi

