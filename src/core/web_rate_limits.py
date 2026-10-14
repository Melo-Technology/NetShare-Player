"""Thread-safe bounded sliding-window limits for the public web API."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable


class WebRateLimiter:
    def __init__(self, *, clock: Callable[[], float] = time.time, max_keys: int = 10_000):
        self.clock = clock
        self.max_keys = max_keys
        self._lock = threading.RLock()
        self._events: dict[str, deque[float]] = {}

    def allow(self, scope: str, identity: str, *, limit: int, window: int) -> tuple[bool, int]:
        now = self.clock()
        key = f"{scope}:{identity}"
        with self._lock:
            if key not in self._events and len(self._events) >= self.max_keys:
                oldest = min(self._events, key=lambda item: self._events[item][-1])
                self._events.pop(oldest, None)
            events = self._events.setdefault(key, deque())
            cutoff = now - window
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return False, max(1, int(events[0] + window - now) + 1)
            events.append(now)
            return True, 0
