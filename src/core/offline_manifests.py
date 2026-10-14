"""Build bounded offline manifests from the existing shared-file index."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath

from src.core.shared_paths import public_shared_path


MAX_REQUEST_PATHS = 100
MAX_MANIFEST_ITEMS = 5000


class OfflineManifestError(ValueError):
    pass


def _normalize_path(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OfflineManifestError("Invalid manifest path")
    raw = value.replace("\\", "/").strip()
    path = PurePosixPath("/" + raw.lstrip("/"))
    if ".." in path.parts:
        raise OfflineManifestError("Invalid manifest path")
    return str(path)


def build_manifest(file_index, requested_paths: list[object]) -> dict:
    """Select indexed files below requested paths without rescanning disk."""
    if not isinstance(requested_paths, list) or not requested_paths:
        raise OfflineManifestError("At least one path is required")
    if len(requested_paths) > MAX_REQUEST_PATHS:
        raise OfflineManifestError("Too many manifest paths")
    roots = tuple(dict.fromkeys(_normalize_path(path) for path in requested_paths))
    items = []
    total_size = 0
    for entry in file_index.snapshot_entries():
        path = public_shared_path(
            str(entry.get("root_slot") or "slot-1"),
            str(entry.get("path") or ""),
        )
        if not any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots):
            continue
        size = max(0, int(entry.get("size") or 0))
        modified = str(entry.get("modified") or "")
        etag = hashlib.sha256(f"{path}\0{size}\0{modified}".encode("utf-8")).hexdigest()
        items.append({"path": path, "size": size, "modified": modified, "etag": etag})
        total_size += size
        if len(items) > MAX_MANIFEST_ITEMS:
            raise OfflineManifestError("Manifest exceeds item limit")
    items.sort(key=lambda item: item["path"])
    digest = hashlib.sha256()
    for item in items:
        digest.update(item["etag"].encode("ascii"))
    return {
        "paths": list(roots),
        "items": items,
        "total_items": len(items),
        "total_size": total_size,
        "etag": digest.hexdigest(),
    }
