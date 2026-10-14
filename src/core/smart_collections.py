"""Bounded smart-collection definitions evaluated on the existing FileIndex."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from src.core.vault_storage import read_json, write_json


MAX_COLLECTIONS = 32
MAX_RULES = 8
MAX_PAGE_SIZE = 100
ALLOWED_RULES = {"file_type", "bpm_min", "bpm_max", "min_size", "recent_days"}
SYSTEM_COLLECTIONS = (
    {"id": "system-recent", "name": "Recently added", "system": True, "rules": {"recent_days": 30}},
    {"id": "system-large", "name": "Large files", "system": True, "rules": {"min_size": 500 * 1024 * 1024}},
    {"id": "system-bpm", "name": "Music 90–110 BPM", "system": True, "rules": {"file_type": "audio", "bpm_min": 90, "bpm_max": 110}},
)


class CollectionError(Exception):
    pass


class SmartCollectionStore:
    def __init__(self, index, path: Path):
        self.index = index
        self.path = path
        self._lock = threading.RLock()
        self._custom = self._load()

    def list(self) -> list[dict]:
        with self._lock:
            return [dict(item) for item in SYSTEM_COLLECTIONS] + [dict(item) for item in self._custom]

    def create(self, name: str, rules: dict) -> dict:
        normalized_name, normalized_rules = self._validate(name, rules)
        with self._lock:
            if len(self._custom) >= MAX_COLLECTIONS:
                raise CollectionError("Collection limit reached")
            item = {"id": uuid.uuid4().hex, "name": normalized_name, "system": False, "rules": normalized_rules}
            self._custom.append(item)
            self._save()
            return dict(item)

    def update(self, collection_id: str, name: str, rules: dict) -> dict:
        normalized_name, normalized_rules = self._validate(name, rules)
        with self._lock:
            item = self._custom_item(collection_id)
            item.update(name=normalized_name, rules=normalized_rules)
            self._save()
            return dict(item)

    def delete(self, collection_id: str) -> None:
        with self._lock:
            item = self._custom_item(collection_id)
            self._custom.remove(item)
            self._save()

    def items(self, collection_id: str, offset: int, limit: int, access_filter=None) -> dict:
        collection = next((item for item in self.list() if item["id"] == collection_id), None)
        if collection is None:
            raise CollectionError("Collection not found")
        entries = [
            entry
            for entry in self.index.snapshot_entries()
            if self._matches(entry, collection["rules"])
            and (access_filter is None or access_filter(entry))
        ]
        entries.sort(key=lambda item: (item.get("modified", ""), item.get("name", "")), reverse=True)
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(int(limit), MAX_PAGE_SIZE))
        return {"items": entries[safe_offset:safe_offset + safe_limit], "total": len(entries), "offset": safe_offset, "has_more": safe_offset + safe_limit < len(entries)}

    @staticmethod
    def _matches(entry: dict, rules: dict) -> bool:
        name = str(entry.get("name", ""))
        if "file_type" in rules:
            from src.core.file_index import FileIndex
            if FileIndex._get_file_category(name) != rules["file_type"]:
                return False
        bpm = entry.get("bpm")
        if "bpm_min" in rules and (bpm is None or bpm < rules["bpm_min"]):
            return False
        if "bpm_max" in rules and (bpm is None or bpm > rules["bpm_max"]):
            return False
        if "min_size" in rules and int(entry.get("size") or 0) < rules["min_size"]:
            return False
        if "recent_days" in rules:
            try:
                modified = datetime.strptime(str(entry.get("modified", "")), "%Y-%m-%d %H:%M")
            except ValueError:
                return False
            if modified < datetime.now() - timedelta(days=rules["recent_days"]):
                return False
        return True

    @staticmethod
    def _validate(name: str, rules: dict) -> tuple[str, dict]:
        clean_name = str(name).strip()
        if not clean_name or len(clean_name) > 80:
            raise CollectionError("Invalid collection name")
        if not isinstance(rules, dict) or not rules or len(rules) > MAX_RULES or set(rules) - ALLOWED_RULES:
            raise CollectionError("Invalid collection rules")
        normalized = {}
        if "file_type" in rules:
            value = str(rules["file_type"]).lower()
            if value not in {"audio", "video", "image", "document", "archive", "other"}:
                raise CollectionError("Invalid file type")
            normalized["file_type"] = value
        for key in ("bpm_min", "bpm_max"):
            if key in rules:
                value = float(rules[key])
                if not 1 <= value <= 400:
                    raise CollectionError("Invalid BPM rule")
                normalized[key] = value
        if normalized.get("bpm_min", 0) > normalized.get("bpm_max", 400):
            raise CollectionError("Invalid BPM range")
        if "min_size" in rules:
            value = int(rules["min_size"])
            if not 0 <= value <= 10 * 1024 * 1024 * 1024:
                raise CollectionError("Invalid size rule")
            normalized["min_size"] = value
        if "recent_days" in rules:
            value = int(rules["recent_days"])
            if not 1 <= value <= 3650:
                raise CollectionError("Invalid recent-days rule")
            normalized["recent_days"] = value
        return clean_name, normalized

    def _custom_item(self, collection_id: str) -> dict:
        item = next((value for value in self._custom if value["id"] == collection_id), None)
        if item is None:
            raise CollectionError("Collection not found")
        return item

    def _load(self) -> list[dict]:
        data = read_json(self.path, purpose="smart-collections", default=[])
        return data if isinstance(data, list) else []

    def _save(self) -> None:
        write_json(self.path, self._custom, purpose="smart-collections")
