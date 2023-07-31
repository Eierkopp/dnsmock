#!python
# -*- coding: utf-8 -*-

import os
import threading
import time

import inotify
import inotify.adapters

from typing import Callable, Dict, Optional, Set


from dnsmock import log


def log_refresh() -> None:
    log(__name__).info("Refresh needed")


class Guard(threading.Thread):
    def __init__(self, guard_time: float, callback: Callable = log_refresh):
        super().__init__()
        self.files: Dict[str, Set[str]] = dict()
        self.keep_running = True
        self.guard_time = guard_time
        self.callback = callback
        self.refresh_at: Optional[float] = None
        self.running = False

    def add_file(self, fname: str) -> None:
        if self.running:
            log(__name__).debug("Guard running, ignoring additional watches")
            return
        fullname = os.path.abspath(fname)
        basename = os.path.basename(fname)
        dirname = os.path.dirname(fullname)
        self.files.setdefault(dirname, set()).add(basename)

    def handle_refresh(self) -> None:
        if self.refresh_at is None:
            return
        if self.refresh_at < time.time():
            self.refresh_at = None
            try:
                self.callback()
            except KeyboardInterrupt:
                raise
            except Exception:
                log(__name__).error("Error in callback", exc_info=True)

    def run(self) -> None:
        self.inotify = inotify.adapters.Inotify()

        for dirname in self.files:
            self.inotify.add_watch(
                dirname,
                (
                    inotify.constants.IN_CLOSE_WRITE
                    | inotify.constants.IN_CREATE
                    | inotify.constants.IN_DELETE
                ),
            )

        while self.keep_running:
            try:
                events = self.inotify.event_gen(yield_nones=False, timeout_s=1)
                events = list(events)
                for event in events:
                    ev, flags, dirname, fname = event
                    if dirname in self.files and fname in self.files[dirname]:
                        self.refresh_at = time.time() + self.guard_time
                        log(__name__).info(
                            "Modification on %s detected", os.path.join(dirname, fname)
                        )
                self.handle_refresh()
            except Exception:
                log(__name__).error("Exception in Guard", exc_info=True)

        log(__name__).info("Guard thread stopped")
        for dirname in self.files:
            self.inotify.remove_watch(dirname)
        self.files = dict()
        self.running = False

    def stop(self) -> None:
        self.keep_running = False
        self.join()
