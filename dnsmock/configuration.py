#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse
from datetime import datetime
import jsonpath_rw_ext as jp
from pprint import pformat
import os
import re
import socket
import sys
from typing import Any, Dict, Optional, Tuple
import yaml

from .logger import logconfig, log

__all__ = ["config"]


class ConfigurationError(ValueError):
    def _init__(self, message: str) -> None:
        ValueError.__init__(self, message)


class ConfigurationCommandError(ValueError):
    def _init__(self, cmd: str) -> None:
        ValueError.__init__(self, f"Malformed command '{cmd}'")


class WideHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["max_help_position"] = 8
        kwargs["width"] = 80
        super(WideHelpFormatter, self).__init__(*args, **kwargs)


class Configuration:
    def __init__(self, fname: str) -> None:
        self.fname = fname
        self.conf_dict = self.load_conf_dict()
        self.arg_parser, self.type_table = self.setup_parser()
        args = self.arg_parser.parse_args()
        self.args = self.handle_interpolation(args)

    def get(self) -> argparse.Namespace:
        return self.args

    def exec_command(self, cmd: str, prm: object) -> object:
        """Execute specified command. Param value is referenced as x."""

        env = dict(re=re, os=os, datetime=datetime, socket=socket)

        try:
            local_vars = dict(x=prm)
            exec(cmd, env, local_vars)
            return local_vars["x"]
        except Exception:
            log(__name__).error("Failed to execute '%s'", cmd)
            log(__name__).debug("Failed to execute '%s'", cmd, exc_info=True)
            raise ConfigurationCommandError(cmd)

    def add_entry(
        self, parser: argparse.ArgumentParser, arg_types: dict, key: str, value: dict
    ) -> None:
        if "commands" in value:
            x = value["default"]
            for cmd in value["commands"]:
                x = self.exec_command(cmd, x)
            value["default"] = x
            del value["commands"]
        if "type" in value:
            value["type"] = eval(value["type"])
        parser.add_argument(f"--{key}", **value)
        arg_types[key] = value.get("type", str)

    def build_key_name(self, prefix: Optional[str], key: str) -> str:
        if prefix is None or prefix == "global":
            return key
        else:
            return "-".join([prefix, key])

    def add_arguments(
        self,
        parser: argparse.ArgumentParser,
        arg_types: dict,
        conf: dict,
        prefix: Optional[str] = None,
    ) -> None:
        for key, value in conf.items():
            if not isinstance(value, dict):
                continue
            key_name = self.build_key_name(prefix, key)
            if "default" in value:
                self.add_entry(parser, arg_types, key_name, value)
            else:
                self.add_arguments(parser, arg_types, value, key_name)

    def setup_parser(self) -> Tuple[argparse.ArgumentParser, dict]:
        arg_types: Dict[str, type] = dict()
        parser = argparse.ArgumentParser("Triparchive", formatter_class=WideHelpFormatter)
        self.add_arguments(parser, arg_types, self.conf_dict, None)
        return parser, arg_types

    def as_type(self, key: str, str_value: str) -> object:
        cvt = self.type_table.get(key, str)
        if cvt.__name__ == "bool":
            return str_value.lower() in ["true", "1", "on", "yes"]
        else:
            return cvt(str_value)

    def handle_interpolation(self, args: argparse.Namespace) -> argparse.Namespace:
        INTERPOLATION_EXPR = re.compile(r"§{([a-z0-9_]+)}")
        arg_dict = args.__dict__
        for i in range(10):
            for key, value in arg_dict.items():
                str_value = str(value)
                m = INTERPOLATION_EXPR.search(str_value)
                if m and m.group(1) in arg_dict:
                    str_value = str_value.replace(m.group(0), str(arg_dict[m.group(1)]))
                    arg_dict[key] = self.as_type(key, str_value)

        return argparse.Namespace(**arg_dict)

    def load_conf_dict(self) -> dict:
        def jp_filter(value: dict, path: str, index: int = 0) -> str:
            result = jp.match(path, value)
            log(__name__).info("Resolving %s -> %s", path, pformat(result))
            if isinstance(result, list):
                result = result[index]
            return str(result)

        log(__name__).info("Reading configuration file %s", self.fname)
        with open(self.fname, encoding="utf8") as f:
            conf_data = f.read()
        config = yaml.safe_load(conf_data)
        if isinstance(config, dict):
            return config
        else:
            log(__name__).error("Invalid configuration")
            sys.exit(1)


def configure_logger(fname: str) -> None:
    with open(fname, encoding="utf8") as f:
        conf_dict = yaml.safe_load(f)
    logconfig(conf_dict["logging"])
    log(__name__).info("Logger configured")


config_name = os.environ.get("DNSMOCK_CONFIG", "/etc/dnsmock/config.yaml")

# Make sure, logger is configured before dumping any configuration.
# Otherwise passwords won't be hidden.
configure_logger(config_name)


if os.path.isfile(config_name):
    configholder = Configuration(config_name)
    config = configholder.get()
else:
    log(__name__).error(
        "Failed to read '%s'. "
        "Please make environment variable 'DNSMOCK_CONFIG' points "
        "to the right configuration file",
        config_name,
    )
    sys.exit(1)

log(__name__).info("Configuration in use:\n%s", pformat(config.__dict__))
