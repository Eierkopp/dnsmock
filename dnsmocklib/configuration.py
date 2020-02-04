#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse
from configparser import ConfigParser, ExtendedInterpolation
import logging
from logging.config import dictConfig
import json
import os
import shlex
import sys
import types

logging.basicConfig(level=logging.DEBUG)


class WideHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def __init__(self, *args, **kwargs):
        kwargs["max_help_position"] = 8
        kwargs["width"] = 80
        super(WideHelpFormatter, self).__init__(*args, **kwargs)


def argname(section, option):
    return (section + "-" + option).lower()


def destname(section, option):
    if section == "global":
        return option.lower()
    return (section + "_" + option).lower()


def get_list(conf, section, option, **kwargs):
    value = conf.get(section, option, **kwargs)
    return [x.strip() for x in shlex.split(value)]


parser = argparse.ArgumentParser(prog='dnsmock',
                                 formatter_class=WideHelpFormatter)

parser.add_argument("--config",
                    help="configuration file location",
                    dest="config",
                    default="/etc/dnsmock/dnsmock.conf")

parser.add_argument("--exthelp",
                    help="extended help",
                    dest="exthelp",
                    action="store_true")


args = parser.parse_known_args()[0]

conf_file = args.config

if not os.access(conf_file, os.R_OK):
    logging.getLogger(__name__).error("Please provide a config file")
    sys.exit(1)

config = ConfigParser(interpolation=ExtendedInterpolation())
config.getlist = types.MethodType(get_list, config)
config.read(conf_file)

parser = argparse.ArgumentParser(prog='dnsmock',
                                 formatter_class=WideHelpFormatter)

parser.add_argument("--config",
                    help="configuration file location",
                    dest="config",
                    default="/etc/dnsmock/dnsmock.conf")

parser.add_argument("--exthelp",
                    help="extended help",
                    dest="exthelp",
                    action="store_true")

for section in config.sections():
    for option in config.options(section):
        if option.endswith("_help"):
            continue
        elif config.has_option(section, option + "_help"):
            help = config.get(section, option + "_help")
            parser.add_argument("--%s" % argname(section, option),
                                help=config.get(section, option + "_help"),
                                dest=destname(section, option),
                                default=config.get(section, option))
        else:
            parser.add_argument("--%s" % argname(section, option),
                                help=argparse.SUPPRESS,
                                dest=destname(section, option),
                                default=config.get(section, option))


if args.exthelp:
    parser.print_help()
    sys.exit(0)

args = parser.parse_args()

if config.has_option("local", "log_config"):
    with open(config.get("local", "log_config")) as f:
        log_config = json.loads(f.read())
        dictConfig(log_config)

for section in config.sections():
    for option in config.options(section):
        if option.endswith("_help"):
            continue
        if hasattr(args, destname(section, option)):
            value = getattr(args, destname(section, option))
            config.set(section,
                       option,
                       value)
