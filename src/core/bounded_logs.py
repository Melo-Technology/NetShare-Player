"""Bounded, loss-signalling primitives for the Tkinter diagnostic views."""

from __future__ import annotations

import queue
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Generic, TypeVar


MIN_LOG_BUFFER_LINES = 200
MAX_LOG_BUFFER_LINES = 5000
DEFAULT_LOG_BUFFER_LINES = 1000
LOG_DRAIN_BUDGET_PER_TICK = 100
REPEAT_FLUSH_SECONDS = 0.75

_T = TypeVar("_T")
_SENSITIVE_KINDS = frozenset({"error", "security"})
_VARIABLE_MESSAGE = re.compile(
    r"(?:[/\\]|\b(?:request|req|trace|session|token|id)\b|\d|[0-9a-f]{8}-[0-9a-f-]{8,})",
    re.IGNORECASE,
)


def clamp_log_buffer_lines(value: object) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        parsed = DEFAULT_LOG_BUFFER_LINES
    return max(MIN_LOG_BUFFER_LINES, min(MAX_LOG_BUFFER_LINES, parsed))


def log_queue_capacity(buffer_lines: object) -> int:
    """Bound producer backlog independently from the visible record buffer."""
    return min(2000, clamp_log_buffer_lines(buffer_lines))


class BoundedEventQueue(Generic[_T]):
    """Non-blocking queue that accounts for every item rejected under load."""

    def __init__(self, maxsize: int):
        self._queue: queue.Queue[_T] = queue.Queue(maxsize=max(1, int(maxsize)))
        self._dropped = 0
        self._drop_lock = threading.Lock()

    @property
    def maxsize(self) -> int:
        return self._queue.maxsize

    def put(self, item: _T) -> bool:
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            with self._drop_lock:
                self._dropped += 1
            return False

    def get_nowait(self) -> _T:
        return self._queue.get_nowait()

    def qsize(self) -> int:
        return self._queue.qsize()

    def consume_dropped(self) -> int:
        with self._drop_lock:
            dropped = self._dropped
            self._dropped = 0
        return dropped

    def resize(self, maxsize: int) -> None:
        """Apply a new bound and account for oldest queued items shed immediately."""
        target = max(1, int(maxsize))
        dropped = 0
        with self._queue.mutex:
            self._queue.maxsize = target
            while len(self._queue.queue) > target:
                self._queue.queue.popleft()
                dropped += 1
            self._queue.not_full.notify_all()
        if dropped:
            with self._drop_lock:
                self._dropped += dropped


@dataclass
class LogRecord:
    timestamp: str
    kind: str
    message: str
    repeat_count: int = 1
    last_seen: float = 0.0
    rendered_repeat_count: int = 0

    @property
    def displayed_lines(self) -> int:
        return 1 + int(self.repeat_count > 1)


@dataclass(frozen=True)
class BufferUpdate:
    record: LogRecord
    repeated: bool
    closed_record: LogRecord | None = None
    evicted_record: LogRecord | None = None


def message_can_be_aggregated(message: str, kind: str) -> bool:
    """Merge only stable diagnostics; paths, IDs, counters and sensitive kinds stay exact."""
    return (
        str(kind).strip().lower() not in _SENSITIVE_KINDS
        and bool(str(message).strip())
        and _VARIABLE_MESSAGE.search(str(message)) is None
    )


class StructuredLogBuffer:
    """Deque-backed records with conservative consecutive-repeat aggregation."""

    def __init__(self, maxlen: int, *, clock=time.monotonic):
        self.maxlen = clamp_log_buffer_lines(maxlen)
        self.records: deque[LogRecord] = deque(maxlen=self.maxlen)
        self._clock = clock

    def add(self, timestamp: str, kind: str, message: str) -> BufferUpdate:
        now = self._clock()
        previous = self.records[-1] if self.records else None
        if (
            previous is not None
            and previous.kind == kind
            and previous.message == message
            and message_can_be_aggregated(message, kind)
        ):
            previous.repeat_count += 1
            previous.last_seen = now
            return BufferUpdate(previous, repeated=True)

        evicted = self.records[0] if len(self.records) == self.maxlen else None
        record = LogRecord(timestamp, kind, message, last_seen=now)
        self.records.append(record)
        return BufferUpdate(
            record, repeated=False, closed_record=previous, evicted_record=evicted,
        )

    def pending_repeat(self, *, force: bool = False) -> LogRecord | None:
        if not self.records:
            return None
        record = self.records[-1]
        if record.repeat_count <= record.rendered_repeat_count:
            return None
        if record.repeat_count <= 1:
            return None
        if force or self._clock() - record.last_seen >= REPEAT_FLUSH_SECONDS:
            return record
        return None

    def mark_repeat_rendered(self, record: LogRecord) -> None:
        record.rendered_repeat_count = record.repeat_count

    def resize(self, maxlen: int) -> int:
        target = clamp_log_buffer_lines(maxlen)
        evicted = max(0, len(self.records) - target)
        self.records = deque(list(self.records)[-target:], maxlen=target)
        self.maxlen = target
        return evicted

    def clear(self) -> None:
        self.records.clear()

    def export_lines(self, repeat_label) -> list[str]:
        lines = []
        for record in self.records:
            lines.append(f"[{record.timestamp}]  {record.message}")
            if record.repeat_count > 1:
                lines.append(f"[{record.timestamp}]  {repeat_label(record.repeat_count)}")
        return lines
