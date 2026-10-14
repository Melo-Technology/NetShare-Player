"""Dedicated Inbox catalogue, bounded reception history and manual import."""

from __future__ import annotations

import shutil
import threading
import time
import uuid
from pathlib import Path

from src.core.content_policy import INBOX_SLOT, resolve_inbox_path
from src.core.shared_paths import resolve_shared_path
from src.core.data_vault import secure_unlink
from src.core.vault_storage import read_json, write_json


MAX_INBOX_HISTORY = 1000


class InboxService:
    def __init__(self, root: Path, history_path: Path):
        self.root = Path(root).resolve()
        self.history_path = Path(history_path)
        self._lock = threading.RLock()

    def list_items(self) -> list[dict]:
        self.root.mkdir(parents=True, exist_ok=True)
        items = []
        for path in sorted(self.root.rglob("*"), key=lambda value: str(value).casefold()):
            if not path.is_file() or any(part.startswith(".") for part in path.relative_to(self.root).parts):
                continue
            stat = path.stat()
            relative = "/" + str(path.relative_to(self.root)).replace("\\", "/")
            items.append({
                "name": path.name, "path": f"/@inbox{relative}",
                "slot": INBOX_SLOT, "relative": relative,
                "size": stat.st_size, "modified_ns": stat.st_mtime_ns,
            })
        return items

    def recent_items(self, limit: int = 5) -> list[dict]:
        bounded = max(0, min(50, int(limit)))
        return sorted(
            self.list_items(), key=lambda item: int(item.get("modified_ns") or 0), reverse=True,
        )[:bounded]

    def history(self, *, offset: int = 0, limit: int | None = None) -> list[dict]:
        with self._lock:
            values = [self._normalize_history_entry(item) for item in reversed(self._read_history_unlocked())]
        start = max(0, int(offset))
        if limit is None:
            return values[start:]
        return values[start:start + max(0, int(limit))]

    def history_capacity(self) -> dict:
        with self._lock:
            count = len(self._read_history_unlocked())
        return {
            "recorded": count,
            "maximum": MAX_INBOX_HISTORY,
            "available": max(0, MAX_INBOX_HISTORY - count),
            "purge_policy": "manual_only",
        }

    def record_received(self, relative: str, size: int, *, source: str = "") -> bool:
        clean_relative = "/" + str(relative).lstrip("/")
        with self._lock:
            entries = self._read_history_unlocked()
            if len(entries) >= MAX_INBOX_HISTORY:
                return False
            entries.append({
                "id": uuid.uuid4().hex,
                "timestamp": time.time(),
                "path": f"/@inbox{clean_relative}",
                "inbox_path": f"/@inbox{clean_relative}",
                "name": Path(clean_relative).name,
                "size": int(size),
                "source": str(source),
                "destination_type": "inbox",
                "destination_slot": INBOX_SLOT,
                "destination_path": clean_relative,
                "status": "received",
            })
            self._write_history_unlocked(entries)
            return True

    def mark_imported(
        self, inbox_path: str, *, destination_slot: str, destination_path: str,
    ) -> bool:
        """Update the most recent matching received record with its final location."""
        with self._lock:
            entries = self._read_history_unlocked()
            for entry in reversed(entries):
                current = str(entry.get("inbox_path") or entry.get("path") or "")
                if current != str(inbox_path):
                    continue
                entry["destination_type"] = "shared"
                entry["destination_slot"] = str(destination_slot)
                entry["destination_path"] = str(destination_path)
                entry["path"] = f"/@shares/{destination_slot}{destination_path if str(destination_path).startswith('/') else '/' + str(destination_path)}"
                entry["status"] = "imported"
                entry["imported_at"] = time.time()
                self._write_history_unlocked(entries)
                return True
        return False

    def purge_history(self) -> int:
        with self._lock:
            count = len(self._read_history_unlocked())
            secure_unlink(self.history_path)
            self._write_history_unlocked([])
            return count

    def import_file(
        self, inbox_path: str, *, destination_slot: str,
        destination_path: str,
    ) -> dict:
        prefix = "/@inbox/"
        if not str(inbox_path).startswith(prefix):
            raise ValueError("invalid Inbox path")
        source = resolve_inbox_path(
            self.root, str(inbox_path)[len(prefix):], require_file=True,
        )
        if source is None:
            raise FileNotFoundError("Inbox file not found")
        destination = resolve_shared_path(
            destination_path, default_slot=destination_slot,
        )
        if destination is None or destination.slot != destination_slot:
            raise ValueError("invalid shared destination")
        if not destination.path.exists() or not destination.path.is_dir():
            raise FileNotFoundError("shared destination not found")
        target = self._unique_path(destination.path / source.path.name)
        shutil.move(str(source.path), str(target))
        relative = "/" + str(target.relative_to(destination.root)).replace("\\", "/")
        self.mark_imported(
            str(inbox_path), destination_slot=destination.slot, destination_path=relative,
        )
        return {"slot": destination.slot, "path": relative, "name": target.name}

    def _read_history_unlocked(self) -> list[dict]:
        value = read_json(self.history_path, purpose="inbox-history", default=[])
        return list(value) if isinstance(value, list) else []

    def _write_history_unlocked(self, entries: list[dict]) -> None:
        write_json(self.history_path, entries, purpose="inbox-history")

    @staticmethod
    def _normalize_history_entry(raw: dict) -> dict:
        entry = dict(raw) if isinstance(raw, dict) else {}
        path = str(entry.get("path") or "")
        inbox_path = str(entry.get("inbox_path") or (path if path.startswith("/@inbox/") else ""))
        destination_type = str(entry.get("destination_type") or ("inbox" if path.startswith("/@inbox/") else "shared"))
        destination_slot = str(entry.get("destination_slot") or (INBOX_SLOT if destination_type == "inbox" else ""))
        destination_path = str(entry.get("destination_path") or (path[len("/@inbox"):] if path.startswith("/@inbox/") else path))
        return {
            "id": str(entry.get("id") or ""),
            "timestamp": float(entry.get("timestamp") or 0.0),
            "path": path,
            "inbox_path": inbox_path,
            "name": str(entry.get("name") or Path(path).name),
            "size": max(0, int(entry.get("size") or 0)),
            "source": str(entry.get("source") or ""),
            "destination_type": destination_type,
            "destination_slot": destination_slot,
            "destination_path": destination_path,
            "status": str(entry.get("status") or ("received" if destination_type == "inbox" else "imported")),
            "imported_at": float(entry.get("imported_at") or 0.0),
        }

    @staticmethod
    def _unique_path(target: Path) -> Path:
        if not target.exists():
            return target
        for index in range(1, 10_000):
            candidate = target.parent / f"{target.stem} ({index}){target.suffix}"
            if not candidate.exists():
                return candidate
        raise OSError("unable to allocate import filename")
