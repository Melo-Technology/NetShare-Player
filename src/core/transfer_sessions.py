"""Bounded, resumable multi-file transfer sessions.

Session metadata and partial chunks live below the configured upload folder so
restarting the HTTP server does not discard progress.  Only metadata is kept in
memory; file payloads are always streamed to disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


CHUNK_SIZE = 1024 * 1024
MAX_ITEMS = 100
MAX_SESSIONS = 64
SESSION_TTL_SECONDS = 24 * 60 * 60

_TRANSFER_ERROR_CODES = {
    "Too many active transfer sessions": "transfer.too_many_sessions",
    "Transfer session is not active": "transfer.session_not_active",
    "Invalid chunk index": "transfer.invalid_chunk_index",
    "Invalid chunk size": "transfer.invalid_chunk_size",
    "Transfer is incomplete": "transfer.incomplete",
    "Transferred size mismatch": "transfer.size_mismatch",
    "Transferred hash mismatch": "transfer.hash_mismatch",
    f"Manifest must contain 1 to {MAX_ITEMS} items": "transfer.invalid_manifest_count",
    "Invalid manifest item": "transfer.invalid_manifest_item",
    "Invalid item size": "transfer.invalid_item_size",
    "Invalid item id": "transfer.invalid_item_id",
    "Invalid filename": "transfer.invalid_filename",
    "Invalid SHA-256": "transfer.invalid_sha256",
    "Invalid destination": "transfer.invalid_destination",
    "Transfer session not found": "transfer.session_not_found",
    "Transfer session expired": "transfer.session_expired",
    "Transfer item not found": "transfer.item_not_found",
    "Unable to allocate destination filename": "transfer.destination_conflict",
}


class TransferError(Exception):
    def __init__(self, message: str, status: int = 400, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code or _TRANSFER_ERROR_CODES.get(message, "transfer.failed")
        self.domain = "transfer"
        self.support_code = "XFER-04" if status in (404, 410) else "XFER-01"


@dataclass(frozen=True)
class TransferItem:
    item_id: str
    filename: str
    size: int
    destination: str
    sha256: str | None



def count_active_transfer_sessions(session_root: Path) -> int:
    """Count non-expired filesystem-backed transfer sessions.

    The helper is intentionally read-only and tolerant of partially written or
    corrupt metadata; reset preflight must never crash the server merely while
    deciding whether an administrative operation is safe.
    """
    root = Path(session_root)
    if not root.exists():
        return 0
    now = time.time()
    count = 0
    try:
        folders = [path for path in root.iterdir() if path.is_dir()]
    except OSError:
        return 0
    for folder in folders:
        try:
            metadata = json.loads((folder / "session.json").read_text(encoding="utf-8"))
            if metadata.get("status") != "active":
                continue
            updated = float(metadata.get("updated_at") or 0.0)
            if now - updated <= SESSION_TTL_SECONDS:
                count += 1
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
    return count

class TransferSessionStore:
    """Thread-safe filesystem-backed store with a bounded session count."""

    def __init__(
        self, root: Path, upload_dirname: str, *, virtual_prefix: str | None = None,
    ):
        self.root = root.resolve()
        self.upload_root = (self.root / upload_dirname).resolve()
        self.session_root = self.upload_root / ".netshare-transfers"
        self.virtual_prefix = str(virtual_prefix or "").rstrip("/")
        self._lock = threading.RLock()

    def validate_manifest(self, manifest: list[dict]) -> list[TransferItem]:
        """Validate a manifest without allocating a session on disk."""
        return self._validate_manifest(manifest)

    def create(self, manifest: list[dict], owner: str) -> dict:
        items = self.validate_manifest(manifest)
        with self._lock:
            self._cleanup_locked()
            sessions = [p for p in self.session_root.glob("*") if p.is_dir()] if self.session_root.exists() else []
            if len(sessions) >= MAX_SESSIONS:
                raise TransferError("Too many active transfer sessions", 429)
            session_id = uuid.uuid4().hex
            folder = self.session_root / session_id
            folder.mkdir(parents=True, exist_ok=False)
            now = time.time()
            metadata = {
                "id": session_id,
                "owner": owner,
                "created_at": now,
                "updated_at": now,
                "status": "active",
                "chunk_size": CHUNK_SIZE,
                "items": [
                    {
                        "id": item.item_id,
                        "filename": item.filename,
                        "size": item.size,
                        "destination": item.destination,
                        "sha256": item.sha256,
                        "received_chunks": [],
                        "committed_path": None,
                    }
                    for item in items
                ],
            }
            self._write_metadata(folder, metadata)
            return self._public(metadata)

    def get(self, session_id: str, owner: str) -> dict:
        with self._lock:
            metadata, _ = self._load_owned(session_id, owner)
            return self._public(metadata)

    def put_chunk(self, session_id: str, item_id: str, chunk_index: int, data: bytes, owner: str) -> dict:
        with self._lock:
            metadata, folder = self._load_owned(session_id, owner)
            if metadata["status"] != "active":
                raise TransferError("Transfer session is not active", 409)
            item = self._find_item(metadata, item_id)
            chunk_count = max(1, (item["size"] + CHUNK_SIZE - 1) // CHUNK_SIZE)
            if chunk_index < 0 or chunk_index >= chunk_count:
                raise TransferError("Invalid chunk index")
            expected = CHUNK_SIZE
            if chunk_index == chunk_count - 1:
                expected = item["size"] - (chunk_index * CHUNK_SIZE)
            if len(data) != expected:
                raise TransferError("Invalid chunk size")
            item_folder = folder / item_id
            item_folder.mkdir(exist_ok=True)
            target = item_folder / f"{chunk_index:08d}.part"
            temporary = target.with_suffix(".tmp")
            temporary.write_bytes(data)
            os.replace(temporary, target)
            received = set(item["received_chunks"])
            received.add(chunk_index)
            item["received_chunks"] = sorted(received)
            metadata["updated_at"] = time.time()
            self._write_metadata(folder, metadata)
            return self._public(metadata)

    def commit(self, session_id: str, owner: str, overwrite: bool = False) -> dict:
        with self._lock:
            metadata, folder = self._load_owned(session_id, owner)
            if metadata["status"] == "committed":
                return self._public(metadata)
            staged: list[tuple[dict, Path]] = []
            for item in metadata["items"]:
                chunk_count = max(1, (item["size"] + CHUNK_SIZE - 1) // CHUNK_SIZE)
                if item["received_chunks"] != list(range(chunk_count)):
                    raise TransferError("Transfer is incomplete", 409)
                assembled = folder / f"{item['id']}.assembled"
                digest = hashlib.sha256()
                written = 0
                with assembled.open("wb") as output:
                    for index in range(chunk_count):
                        chunk = (folder / item["id"] / f"{index:08d}.part").read_bytes()
                        output.write(chunk)
                        digest.update(chunk)
                        written += len(chunk)
                if written != item["size"]:
                    assembled.unlink(missing_ok=True)
                    raise TransferError("Transferred size mismatch", 409)
                if item["sha256"] and digest.hexdigest() != item["sha256"]:
                    assembled.unlink(missing_ok=True)
                    raise TransferError("Transferred hash mismatch", 409)
                staged.append((item, assembled))

            committed = []
            for item, assembled in staged:
                destination = self._destination(item["destination"])
                destination.mkdir(parents=True, exist_ok=True)
                target = (destination / item["filename"]).resolve()
                self._ensure_below(target, self.upload_root)
                if target.exists() and not overwrite:
                    target = self._unique_path(target)
                os.replace(assembled, target)
                relative = "/" + str(target.relative_to(self.upload_root)).replace("\\", "/")
                item["committed_path"] = (
                    f"{self.virtual_prefix}{relative}" if self.virtual_prefix
                    else "/" + str(target.relative_to(self.root)).replace("\\", "/")
                )
                committed.append(item["committed_path"])
            metadata["status"] = "committed"
            metadata["updated_at"] = time.time()
            self._write_metadata(folder, metadata)
            return {**self._public(metadata), "paths": committed}

    def delete(self, session_id: str, owner: str) -> None:
        with self._lock:
            _, folder = self._load_owned(session_id, owner)
            shutil.rmtree(folder)

    def _validate_manifest(self, manifest: list[dict]) -> list[TransferItem]:
        if not isinstance(manifest, list) or not manifest or len(manifest) > MAX_ITEMS:
            raise TransferError(f"Manifest must contain 1 to {MAX_ITEMS} items")
        result = []
        seen = set()
        for raw in manifest:
            if not isinstance(raw, dict):
                raise TransferError("Invalid manifest item")
            item_id = str(raw.get("id", "")).strip()
            filename = str(raw.get("filename", "")).strip()
            destination = str(raw.get("destination", "/")).strip() or "/"
            sha256 = raw.get("sha256")
            try:
                size = int(raw.get("size"))
            except (TypeError, ValueError):
                raise TransferError("Invalid item size") from None
            if not item_id or item_id in seen or len(item_id) > 80 or not item_id.replace("-", "").replace("_", "").isalnum():
                raise TransferError("Invalid item id")
            if not filename or Path(filename).name != filename or filename in (".", ".."):
                raise TransferError("Invalid filename")
            if size < 0:
                raise TransferError("Invalid item size")
            if sha256 is not None and (not isinstance(sha256, str) or len(sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha256)):
                raise TransferError("Invalid SHA-256")
            self._destination(destination)
            seen.add(item_id)
            result.append(TransferItem(item_id, filename, size, destination, sha256.lower() if sha256 else None))
        return result

    def _destination(self, relative: str) -> Path:
        clean = relative.lstrip("/\\")
        destination = (self.upload_root / clean).resolve()
        self._ensure_below(destination, self.upload_root)
        return destination

    @staticmethod
    def _ensure_below(path: Path, root: Path) -> None:
        try:
            path.relative_to(root)
        except ValueError:
            raise TransferError("Invalid destination", 403) from None

    def _load_owned(self, session_id: str, owner: str) -> tuple[dict, Path]:
        if len(session_id) != 32 or any(c not in "0123456789abcdef" for c in session_id):
            raise TransferError("Transfer session not found", 404)
        folder = self.session_root / session_id
        try:
            metadata = json.loads((folder / "session.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise TransferError("Transfer session not found", 404) from None
        if metadata.get("owner") != owner:
            raise TransferError("Transfer session not found", 404)
        if time.time() - float(metadata.get("updated_at", 0)) > SESSION_TTL_SECONDS:
            shutil.rmtree(folder, ignore_errors=True)
            raise TransferError("Transfer session expired", 410)
        return metadata, folder

    @staticmethod
    def _find_item(metadata: dict, item_id: str) -> dict:
        for item in metadata["items"]:
            if item["id"] == item_id:
                return item
        raise TransferError("Transfer item not found", 404)

    @staticmethod
    def _write_metadata(folder: Path, metadata: dict) -> None:
        temporary = folder / "session.json.tmp"
        temporary.write_text(json.dumps(metadata, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, folder / "session.json")

    @staticmethod
    def _public(metadata: dict) -> dict:
        return {key: value for key, value in metadata.items() if key != "owner"}

    @staticmethod
    def _unique_path(target: Path) -> Path:
        for index in range(1, 10_000):
            candidate = target.parent / f"{target.stem} ({index}){target.suffix}"
            if not candidate.exists():
                return candidate
        raise TransferError("Unable to allocate destination filename", 409)

    def _cleanup_locked(self) -> None:
        if not self.session_root.exists():
            return
        cutoff = time.time() - SESSION_TTL_SECONDS
        for folder in self.session_root.iterdir():
            if folder.is_dir() and folder.stat().st_mtime < cutoff:
                shutil.rmtree(folder, ignore_errors=True)
