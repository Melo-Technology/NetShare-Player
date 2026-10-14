"""Bounded, local JSON Lines audit trail for cluster governance events."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


MAX_AUDIT_EVENTS = 1000
MAX_RETURNED_EVENTS = 200


class ClusterAuditLog:
    def __init__(self, path: Path, *, max_events: int = MAX_AUDIT_EVENTS):
        self.path = Path(path)
        self.max_events = max(1, int(max_events))
        self._lock = threading.RLock()

    def record(self, event: str, *, node_id: str = "", **details) -> bool:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": str(event),
        }
        if node_id:
            entry["node_id"] = str(node_id)
        entry.update({key: value for key, value in details.items() if value is not None})
        try:
            with self._lock:
                entries = self._read_unlocked()
                entries.append(entry)
                self._write_unlocked(entries[-self.max_events:])
            return True
        except OSError:
            return False

    def list_events(self, limit: int = MAX_RETURNED_EVENTS) -> list[dict]:
        bounded = max(1, min(int(limit), MAX_RETURNED_EVENTS))
        with self._lock:
            return list(reversed(self._read_unlocked()[-bounded:]))

    def _read_unlocked(self) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        entries = []
        for line in lines[-self.max_events:]:
            try:
                value = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict):
                entries.append(value)
        return entries

    def _write_unlocked(self, entries: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            "".join(
                json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n"
                for entry in entries
            ),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)
