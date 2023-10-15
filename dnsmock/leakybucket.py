#!/usr/bin/python3
# coding: utf-8

from collections import deque
import time
from typing import Deque, List, Optional, Tuple


class LeakyBucket:
    NULL = 0.0

    def __init__(self, schedule: List[Tuple[float, int]]) -> None:
        self.schedule = schedule
        self.schedule.sort()
        self.max_count = max([x for _, x in schedule])
        self.ticks: Deque[float] = deque()

    def must_wait(self, now: float) -> float:
        """Compute required time to wait. Return NULL, if adding is possible"""
        while len(self.ticks) > self.max_count:
            self.ticks.popleft()
        wait_time = self.NULL
        length = len(self.ticks)
        for interval, count in self.schedule:
            if length < count:
                continue
            td = self.ticks[-count] + interval - now
            if td > wait_time:
                wait_time = td
        return wait_time

    def try_add(self) -> bool:
        now = time.time()
        wait_time = self.must_wait(now)
        if wait_time > self.NULL:
            return False
        self.ticks.append(now)
        return True

    def add(self) -> None:
        now = time.time()
        wait_time = self.must_wait(now)
        while wait_time:
            time.sleep(wait_time)
            now = time.time()
            wait_time = self.must_wait(now)
        self.ticks.append(now)


# start = time.time()
# lb = LeakyBucket([(10, 3), (3, 1)])
# for i in range(10):
#     lb.add()
#     print("%0.3f" % (time.time() - start))
