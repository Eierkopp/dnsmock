#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import functools
import logging
import logging.config
import os
import re
from typing import Any, Callable, Dict, List

__all__ = ["log", "logconfig", "log_exception"]

DEFAULT_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DEFAULT_DF = "%Y%m%d_%H%M%S"

logging.basicConfig(level=logging.DEBUG, format=DEFAULT_FMT, datefmt=DEFAULT_DF)
log = logging.getLogger


class IncludeOnly(logging.Filter):
    def __init__(self, mask: str) -> None:
        self.mask = re.compile(mask)

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Return True, if mask matches
        """

        return True if self.mask.match(record.msg) else False


class HidePart(logging.Filter):
    def __init__(self, mask: str, replacement: str = "***") -> None:
        self.mask = re.compile(mask, re.MULTILINE)
        self.replacement = replacement

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Replace all occurrences of mask with replacement
        """

        def replace_in(msg: Any) -> Any:
            if not isinstance(msg, str):
                return msg
            res = ""
            pos = 0
            for m in self.mask.finditer(msg):
                for i in range(len(m.groups())):
                    if m.group(i + 1) is not None:
                        start, end = m.span(i + 1)
                        res += msg[pos:start] + self.replacement
                        pos = end
            res += msg[pos:]
            return res

        record.msg = replace_in(record.msg)
        if record.args:
            record.args = tuple(replace_in(arg) for arg in record.args)
        return True


def expand_filenames(config: dict) -> None:
    """Allow ~ in filenames"""
    for handler in config.get("handlers", dict()).values():
        if "filename" in handler:
            fname = os.path.expanduser(handler["filename"])
            handler["filename"] = fname
            dirname = os.path.dirname(fname)
            try:
                os.makedirs(dirname, exist_ok=True)
            except PermissionError as e:
                log(__name__).error("Insufficient access rights for %s", dir(e))


def log_exception(function: Callable[[Any, Any, Any], Any]) -> Callable:
    module = function.__module__
    myname = module + "." + function.__name__
    exclog = log(module)

    if asyncio.iscoroutinefunction(function):

        @functools.wraps(function)
        async def wrapper(*args: List[Any], **kwargs: Dict[str, Any]) -> Any:
            try:
                return await function(*args, **kwargs)
            except Exception:
                exclog.error("Exception in " + myname, exc_info=True)

        return wrapper

    else:

        @functools.wraps(function)
        def wrapper(*args: List[Any], **kwargs: Dict[str, Any]) -> Any:
            try:
                return function(*args, **kwargs)
            except Exception:
                exclog.error("Exception in " + myname, exc_info=True)

        return wrapper


def logconfig(config: dict) -> None:
    """Use config structure to setup loggers

    params:
    config - dict containig the configuration
    """

    try:
        expand_filenames(config)
        logging.config.dictConfig(config)
    except Exception:
        log(__name__).warning("Using fallback logging configuration", exc_info=True)
