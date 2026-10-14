"""Bounded per-device favorites and annotations with composite identities."""

from __future__ import annotations

import threading
from pathlib import Path, PurePosixPath

from src.core.shared_paths import parse_shared_path
from src.core.shared_paths import encode_shared_path, resolve_shared_path
from src.core.shared_roots import ROOT_SLOTS
from src.core.vault_storage import read_json, write_json


MAX_FAVORITES_PER_DEVICE = 500
MAX_ANNOTATION_CHARS = 2000


class UserMetadataError(ValueError):
    pass


class UserMetadataStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._devices = self._load()

    def list_stored(self, device_id: str) -> list[dict]:
        owner = self._device_id(device_id)
        with self._lock:
            return [dict(item) for item in self._devices.get(owner, [])]

    def list(self, device_id: str) -> list[dict]:
        """Return stored entries without dropping unavailable identities."""
        import src.state as state
        result = []
        for item in self.list_stored(device_id):
            slot = item["root_slot"]
            root_active = state.root_for_slot(slot) is not None
            resolved = resolve_shared_path(
                item["path"], default_slot=slot,
                visible=True, require_file=True,
            ) if root_active else None
            available = resolved is not None
            result.append({
                **item,
                "name": PurePosixPath(item["path"]).name,
                "virtual_path": encode_shared_path(slot, item["path"]),
                "available": available,
                "unavailable_reason": "" if available else (
                    "hidden_or_missing" if root_active else "root_unavailable"
                ),
            })
        return result

    def upsert(
        self, device_id: str, root_slot: str, path: str,
        annotation: str = "",
    ) -> dict:
        owner = self._device_id(device_id)
        slot, relative = self._identity(root_slot, path)
        note = str(annotation)
        if len(note) > MAX_ANNOTATION_CHARS:
            raise UserMetadataError("Annotation is too long")
        with self._lock:
            items = self._devices.setdefault(owner, [])
            existing = next(
                (item for item in items
                 if item["root_slot"] == slot and item["path"] == relative),
                None,
            )
            if existing is None:
                if len(items) >= MAX_FAVORITES_PER_DEVICE:
                    raise UserMetadataError("Favorite limit reached")
                existing = {
                    "root_slot": slot, "path": relative,
                    "annotation": note,
                }
                items.append(existing)
            else:
                existing["annotation"] = note
            self._save_locked()
            return dict(existing)

    def remove(self, device_id: str, root_slot: str, path: str) -> bool:
        owner = self._device_id(device_id)
        slot, relative = self._identity(root_slot, path)
        with self._lock:
            items = self._devices.get(owner, [])
            kept = [
                item for item in items
                if not (
                    item["root_slot"] == slot and item["path"] == relative
                )
            ]
            if len(kept) == len(items):
                return False
            if kept:
                self._devices[owner] = kept
            else:
                self._devices.pop(owner, None)
            self._save_locked()
            return True

    @staticmethod
    def _device_id(value: str) -> str:
        clean = str(value).strip()
        if not clean or len(clean) > 256:
            raise UserMetadataError("Invalid device identity")
        return clean

    @staticmethod
    def _identity(root_slot: str, path: str) -> tuple[str, str]:
        slot = str(root_slot).strip()
        if slot not in ROOT_SLOTS:
            raise UserMetadataError("Favorites require an active shared-root slot")
        parsed = parse_shared_path(str(path), default_slot=slot)
        if parsed is None or parsed[0] != slot:
            raise UserMetadataError("Favorite slot and path do not match")
        relative = PurePosixPath("/" + str(parsed[1]).replace("\\", "/").lstrip("/"))
        if relative == PurePosixPath("/") or ".." in relative.parts:
            raise UserMetadataError("Invalid favorite path")
        return slot, str(relative)

    def _load(self) -> dict[str, list[dict]]:
        value = read_json(self.path, purpose="user-metadata", default={})
        devices = value.get("devices", {}) if isinstance(value, dict) else {}
        if not isinstance(devices, dict):
            return {}
        result = {}
        for owner, raw_items in devices.items():
            items = []
            if not isinstance(raw_items, list):
                continue
            for raw in raw_items[:MAX_FAVORITES_PER_DEVICE]:
                try:
                    slot, relative = self._identity(
                        raw.get("root_slot", ""), raw.get("path", ""),
                    )
                    note = str(raw.get("annotation", ""))[:MAX_ANNOTATION_CHARS]
                    items.append({
                        "root_slot": slot, "path": relative,
                        "annotation": note,
                    })
                except (AttributeError, UserMetadataError):
                    continue
            if items:
                result[str(owner)] = items
        return result

    def _save_locked(self) -> None:
        write_json(self.path, {"devices": self._devices}, purpose="user-metadata")
