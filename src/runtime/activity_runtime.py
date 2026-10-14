"""Non-destructive producer-side fan-out for logs, writes and live transfers.

Legacy Tkinter remains the sole consumer of ``state._log_queue`` and
``state._write_activity_queue``. Producers tee detached copies into this
independent bounded runtime so WebView never steals from single-consumer queues.
"""
from __future__ import annotations

from collections import deque, OrderedDict
from threading import RLock
import time
import uuid
from typing import Any, Callable

from src.core.bounded_logs import clamp_log_buffer_lines
from src.secret_redaction import redact_secret_text


Subscriber = Callable[[dict[str, Any]], None]


class ActivityRuntime:
    def __init__(self, capacity: int = 1000):
        self._lock = RLock()
        self._capacity = clamp_log_buffer_lines(capacity)
        self._logs: deque[dict[str, Any]] = deque(maxlen=self._capacity)
        self._writes: deque[dict[str, Any]] = deque(maxlen=self._capacity)
        self._transfers: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._subscribers: dict[str, Subscriber] = {}
        self._dropped_subscriber_deliveries = 0

    @property
    def capacity(self) -> int:
        with self._lock:
            return self._capacity

    def resize(self, capacity: int) -> int:
        target = clamp_log_buffer_lines(capacity)
        with self._lock:
            old_total = len(self._logs) + len(self._writes) + len(self._transfers)
            self._logs = deque(list(self._logs)[-target:], maxlen=target)
            self._writes = deque(list(self._writes)[-target:], maxlen=target)
            while len(self._transfers) > target:
                self._transfers.popitem(last=False)
            self._capacity = target
            return max(0, old_total - len(self._logs) - len(self._writes) - len(self._transfers))

    def clear(self) -> dict[str, int]:
        """Clear reportable live activity without touching configuration."""
        with self._lock:
            counts = {
                "logs": len(self._logs),
                "write_activity": len(self._writes),
                "transfers": len(self._transfers),
            }
            self._logs.clear()
            self._writes.clear()
            self._transfers.clear()
            self._dropped_subscriber_deliveries = 0
            return counts

    def publish_log(self, message: str, kind: str = "info", *, timestamp: float | None = None) -> dict[str, Any]:
        event = {
            "stream": "log",
            "message": redact_secret_text(message),
            "kind": str(kind or "info"),
            "time": float(timestamp if timestamp is not None else time.time()),
        }
        with self._lock:
            self._logs.append(dict(event))
        self._notify(event)
        return event

    def publish_write(self, event: dict[str, Any]) -> dict[str, Any]:
        detached = {
            "stream": "write",
            "action": str(event.get("action") or "write"),
            "path": str(event.get("path") or ""),
            "size": int(event["size"]) if event.get("size") is not None else None,
            "client": str(event.get("client") or ""),
            "request_id": str(event.get("request_id") or ""),
            "time": float(event.get("time") or time.time()),
        }
        with self._lock:
            self._writes.append(dict(detached))
        self._notify(detached)
        return detached

    def publish_transfer(self, event: dict[str, Any]) -> dict[str, Any]:
        """Upsert one bounded live-transfer record and fan out its latest state."""
        transfer_id = str(event.get("id") or event.get("transfer_id") or "").strip()
        if not transfer_id:
            raise ValueError("transfer id is required")
        now = float(event.get("time") or time.time())
        with self._lock:
            previous = dict(self._transfers.get(transfer_id) or {})
            total_bytes = max(0, int(event.get("total_bytes", previous.get("total_bytes", 0)) or 0))
            received_bytes = max(0, int(event.get("received_bytes", previous.get("received_bytes", 0)) or 0))
            status = str(event.get("status", previous.get("status", "receiving")) or "receiving")
            created_at = float(previous.get("created_at") or event.get("created_at") or now)

            speed_bps = previous.get("speed_bps")
            previous_received = max(0, int(previous.get("received_bytes", 0) or 0))
            previous_time = float(previous.get("time") or now)
            delta_bytes = max(0, received_bytes - previous_received)
            delta_seconds = max(0.0, now - previous_time)
            if delta_bytes > 0 and delta_seconds > 0:
                instant_speed = delta_bytes / delta_seconds
                try:
                    old_speed = float(speed_bps or 0.0)
                except (TypeError, ValueError):
                    old_speed = 0.0
                speed_bps = instant_speed if old_speed <= 0 else (old_speed * 0.65 + instant_speed * 0.35)
            if status in {"completed", "committed"} and received_bytes > 0 and now > created_at:
                # A completed transfer should leave a useful final value on the
                # Overview instead of immediately reverting to "Unavailable".
                speed_bps = received_bytes / (now - created_at)

            detached = {
                **previous,
                "stream": "transfer",
                "id": transfer_id,
                "filename": str(event.get("filename", previous.get("filename", "")) or ""),
                "file_count": max(1, int(event.get("file_count", previous.get("file_count", 1)) or 1)),
                "total_bytes": total_bytes,
                "received_bytes": received_bytes,
                "progress": max(0.0, min(1.0, float(event.get("progress", previous.get("progress", 0.0)) or 0.0))),
                "status": status,
                "client": str(event.get("client", previous.get("client", "")) or ""),
                "path": str(event.get("path", previous.get("path", "")) or ""),
                "request_id": str(event.get("request_id", previous.get("request_id", "")) or ""),
                "created_at": created_at,
                "speed_bps": None if speed_bps is None else max(0.0, float(speed_bps)),
                "time": now,
            }
            self._transfers.pop(transfer_id, None)
            self._transfers[transfer_id] = dict(detached)
            while len(self._transfers) > self._capacity:
                self._transfers.popitem(last=False)
        self._notify(detached)
        return detached

    def transfer_speed_bps(self) -> float | None:
        """Return current aggregate speed, or the most recent completed speed."""
        with self._lock:
            records = list(self._transfers.values())
        active = []
        for item in records:
            if str(item.get("status") or "").lower() not in {"receiving", "uploading"}:
                continue
            try:
                speed = float(item.get("speed_bps"))
            except (TypeError, ValueError):
                continue
            if speed > 0:
                active.append(speed)
        if active:
            return sum(active)
        for item in reversed(records):
            try:
                speed = float(item.get("speed_bps"))
            except (TypeError, ValueError):
                continue
            if speed > 0:
                return speed
        return None

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "logs": [dict(item) for item in self._logs],
                "write_activity": [dict(item) for item in self._writes],
                "transfers": [dict(item) for item in self._transfers.values()],
                "capacity": self._capacity,
                "subscriber_delivery_failures": self._dropped_subscriber_deliveries,
            }

    def subscribe(self, callback: Subscriber) -> str:
        if not callable(callback):
            raise TypeError("callback must be callable")
        token = uuid.uuid4().hex
        with self._lock:
            self._subscribers[token] = callback
        return token

    def unsubscribe(self, token: str) -> bool:
        with self._lock:
            return self._subscribers.pop(str(token), None) is not None

    def _notify(self, event: dict[str, Any]) -> None:
        with self._lock:
            callbacks = tuple(self._subscribers.values())
        for callback in callbacks:
            try:
                callback(dict(event))
            except Exception:
                # A UI/event subscriber can never affect legacy queues/producers.
                with self._lock:
                    self._dropped_subscriber_deliveries += 1


activity_runtime = ActivityRuntime()

__all__ = ["ActivityRuntime", "activity_runtime"]
