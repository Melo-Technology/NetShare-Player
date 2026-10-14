"""Filesystem-backed E2E Player-to-Player ciphertext relay (Chantier B2).

The relay deliberately knows nothing about content keys.  It persists only
signed public metadata, token hashes, and ciphertext chunks so a process
restart does not discard an accepted cross-network transfer.
"""
from __future__ import annotations

import hashlib
import json
import errno
import os
import secrets
import shutil
import threading
import time
from pathlib import Path

RELAY_PROTOCOL = "NSP2P-RELAY"
RELAY_VERSION = 1
CLEAR_CHUNK_SIZE = 4 * 1024 * 1024
AES_GCM_ENVELOPE_OVERHEAD = 28  # 12-byte nonce + 16-byte tag
MAX_ITEMS = 100
MAX_SESSIONS = 64
MAX_RELAY_CLEAR_BYTES = 64 * 1024 * 1024 * 1024  # 64 GiB; product target >=10 GiB
MAX_RELAY_STORE_BYTES = 128 * 1024 * 1024 * 1024
MIN_TTL_SECONDS = 5 * 60
MAX_TTL_SECONDS = 48 * 60 * 60
DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_METADATA_BYTES = 256 * 1024
MIN_FREE_SPACE_BYTES = 64 * 1024 * 1024
REPLICA_MAX_PAYLOAD_BYTES = CLEAR_CHUNK_SIZE + AES_GCM_ENVELOPE_OVERHEAD


class P2PRelayError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class P2PRelayStore:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self._lock = threading.RLock()

    def accept(self, *, invitation: dict, acceptance: dict, receiver_token: str | None = None) -> dict:
        invite_id = str(invitation.get("invite_id", "")).strip()
        binding = str(invitation.get("session_binding", "")).strip()
        if not _hex(invite_id, 32) or not _hex(binding, 64):
            raise P2PRelayError("Invalid invitation binding")
        if not isinstance(acceptance, dict):
            raise P2PRelayError("Invalid receiver acceptance")
        if acceptance.get("protocol") != "NSP2P-RELAY-ACCEPT" or acceptance.get("version") != 1:
            raise P2PRelayError("Unsupported receiver acceptance")
        if acceptance.get("invite_id") != invite_id or acceptance.get("invitation_binding") != binding:
            raise P2PRelayError("Receiver acceptance binding mismatch")

        with self._lock:
            self._cleanup_locked()
            existing = self._find_by_invitation_locked(invite_id)
            supplied_token = str(receiver_token or "").strip()
            token = supplied_token or secrets.token_urlsafe(32)
            if len(token) < 32 or len(token) > 256:
                raise P2PRelayError("Invalid relay receiver capability")
            token_hash = _hash_token(token)
            if existing is not None:
                metadata, _folder = existing
                # B3: accepting is idempotent only for the exact same signed
                # acceptance and the same receiver-generated capability. This
                # lets a receiver recover when the 201 response is lost without
                # turning a consumed invitation into a reusable bearer token.
                if (metadata.get("acceptance") == acceptance
                        and metadata.get("receiver_token_hash") == token_hash):
                    return {
                        "relay_id": metadata["relay_id"],
                        "token": token,
                        "expires_at": metadata["expires_at"],
                        "status": metadata["status"],
                        "idempotent": True,
                    }
                raise P2PRelayError("Invitation already accepted", 409)
            if self._active_count_locked() >= MAX_SESSIONS:
                raise P2PRelayError("Too many active relay sessions", 429)
            relay_id = secrets.token_hex(16)
            now = time.time()
            folder = self.root / relay_id
            folder.mkdir(parents=True, exist_ok=False)
            files = invitation.get("files") if isinstance(invitation.get("files"), list) else []
            metadata = {
                "protocol": RELAY_PROTOCOL,
                "version": RELAY_VERSION,
                "relay_id": relay_id,
                "invitation_id": invite_id,
                "invitation_binding": binding,
                "invitation_files": files,
                "acceptance": acceptance,
                "receiver_token_hash": token_hash,
                "sender_owner": None,
                "created_at": now,
                "updated_at": now,
                "expires_at": now + DEFAULT_TTL_SECONDS,
                "status": "accepted",
                "descriptor": None,
                "completion": None,
                "items": [],
            }
            self._write_metadata(folder, metadata)
            return {
                "relay_id": relay_id,
                "token": token,
                "expires_at": metadata["expires_at"],
                "status": metadata["status"],
            }

    def retry_accept(self, *, invitation_id: str, acceptance: dict, receiver_token: str) -> dict:
        """Recover a lost 201 response after the invitation access was consumed."""
        token = str(receiver_token or "").strip()
        if len(token) < 32 or len(token) > 256:
            raise P2PRelayError("Invalid relay receiver capability", 410)
        with self._lock:
            self._cleanup_locked()
            existing = self._find_by_invitation_locked(invitation_id)
            if existing is None:
                raise P2PRelayError("Invitation already consumed or expired", 410)
            metadata, _folder = existing
            if (metadata.get("acceptance") != acceptance
                    or metadata.get("receiver_token_hash") != _hash_token(token)):
                raise P2PRelayError("Invitation already consumed or expired", 410)
            return {
                "relay_id": metadata["relay_id"],
                "token": token,
                "expires_at": metadata["expires_at"],
                "status": metadata["status"],
                "idempotent": True,
            }

    def sender_status(self, invitation_id: str) -> dict:
        with self._lock:
            self._cleanup_locked()
            found = self._find_by_invitation_locked(invitation_id)
            if found is None:
                raise P2PRelayError("Relay session not found", 404)
            metadata, _ = found
            return self._public(metadata)

    def configure(self, *, invitation_id: str, owner: str, descriptor: dict, items: list[dict], ttl_seconds: int) -> dict:
        if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
            raise P2PRelayError("Invalid relay lifetime")
        with self._lock:
            self._cleanup_locked()
            found = self._find_by_invitation_locked(invitation_id)
            if found is None:
                raise P2PRelayError("Relay session not found", 404)
            metadata, folder = found
            if metadata["status"] not in ("accepted", "uploading"):
                raise P2PRelayError("Relay session cannot be configured", 409)
            current_owner = metadata.get("sender_owner")
            if current_owner not in (None, owner):
                raise P2PRelayError("Relay session owner mismatch", 403)
            if not isinstance(descriptor, dict) or descriptor.get("protocol") != "NSP2P-RELAY" or descriptor.get("version") != 1:
                raise P2PRelayError("Invalid relay descriptor")
            if (descriptor.get("invite_id") != invitation_id
                    or descriptor.get("invitation_binding") != metadata["invitation_binding"]
                    or descriptor.get("relay_id") != metadata["relay_id"]):
                raise P2PRelayError("Relay descriptor binding mismatch")
            normalized, total = self._validate_items(items, metadata.get("invitation_files") or [])
            descriptor_files = descriptor.get("files")
            expected_files = [
                {key: item[key] for key in ("id", "filename", "clear_size", "chunk_count", "ciphertext_size")}
                for item in normalized
            ]
            if descriptor_files != expected_files:
                raise P2PRelayError("Relay descriptor manifest mismatch")
            existing_total = self._reserved_bytes_locked(exclude_relay_id=metadata["relay_id"])
            if existing_total + total > MAX_RELAY_STORE_BYTES:
                raise P2PRelayError("Relay storage quota exceeded", 413)
            if metadata["status"] == "uploading":
                if metadata.get("descriptor") != descriptor:
                    raise P2PRelayError("Relay descriptor cannot change during upload", 409)
                prior = {item["id"]: item for item in metadata.get("items") or []}
                for item in normalized:
                    old_item = prior.get(item["id"])
                    if old_item is not None:
                        item["received_chunks"] = list(old_item.get("received_chunks") or [])
                        item["chunk_hashes"] = dict(old_item.get("chunk_hashes") or {})
            metadata["sender_owner"] = owner
            metadata["descriptor"] = descriptor
            metadata["items"] = normalized
            metadata["status"] = "uploading"
            now = time.time()
            metadata["updated_at"] = now
            metadata["expires_at"] = now + ttl_seconds
            self._write_metadata(folder, metadata)
            return self._public(metadata)

    def put_chunk(self, *, relay_id: str, item_id: str, chunk_index: int, data: bytes, owner: str) -> dict:
        with self._lock:
            metadata, folder = self._load_locked(relay_id)
            self._require_owner(metadata, owner)
            if metadata["status"] != "uploading":
                raise P2PRelayError("Relay session is not uploading", 409)
            item = self._item(metadata, item_id)
            if chunk_index < 0 or chunk_index >= item["chunk_count"]:
                raise P2PRelayError("Invalid relay chunk index")
            expected = self._expected_cipher_chunk_size(item, chunk_index)
            if len(data) != expected:
                raise P2PRelayError("Invalid relay chunk size")
            item_folder = folder / "chunks" / item_id
            try:
                usage = shutil.disk_usage(self.root.parent if self.root.parent.exists() else Path.cwd())
                if usage.free < len(data) + MIN_FREE_SPACE_BYTES:
                    raise P2PRelayError("Relay storage is full", 507)
                item_folder.mkdir(parents=True, exist_ok=True)
                target = item_folder / f"{chunk_index:08d}.bin"
                tmp = target.with_suffix(".tmp")
                with tmp.open("wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, target)
            except P2PRelayError:
                raise
            except OSError as error:
                if error.errno in (errno.ENOSPC, errno.EDQUOT):
                    raise P2PRelayError("Relay storage is full", 507) from None
                raise P2PRelayError("Relay storage write failed", 500) from error
            received = set(item.get("received_chunks") or [])
            received.add(chunk_index)
            item["received_chunks"] = sorted(received)
            hashes = dict(item.get("chunk_hashes") or {})
            hashes[str(chunk_index)] = hashlib.sha256(data).hexdigest()
            item["chunk_hashes"] = hashes
            metadata["updated_at"] = time.time()
            self._write_metadata(folder, metadata)
            return {"ok": True, "received_chunks": item["received_chunks"]}

    def commit(self, *, relay_id: str, owner: str, completion: dict) -> dict:
        with self._lock:
            metadata, folder = self._load_locked(relay_id)
            self._require_owner(metadata, owner)
            if metadata["status"] == "ready":
                return self._public(metadata)
            if metadata["status"] != "uploading":
                raise P2PRelayError("Relay session is not uploading", 409)
            for item in metadata["items"]:
                if item.get("received_chunks") != list(range(item["chunk_count"])):
                    raise P2PRelayError("Relay upload is incomplete", 409)
            if not isinstance(completion, dict) or completion.get("protocol") != "NSP2P-RELAY-COMPLETE" or completion.get("version") != 1:
                raise P2PRelayError("Invalid relay completion")
            if completion.get("relay_id") != relay_id or completion.get("invite_id") != metadata["invitation_id"]:
                raise P2PRelayError("Relay completion binding mismatch")
            completion_files = completion.get("files")
            if not isinstance(completion_files, list):
                raise P2PRelayError("Invalid relay completion")
            completion_ids = [str(item.get("id", "")) for item in completion_files if isinstance(item, dict)]
            expected_ids = [item["id"] for item in metadata["items"]]
            if len(completion_ids) != len(expected_ids) or set(completion_ids) != set(expected_ids):
                raise P2PRelayError("Relay completion manifest mismatch")
            metadata["completion"] = completion
            metadata["status"] = "ready"
            metadata["updated_at"] = time.time()
            self._write_metadata(folder, metadata)
            return self._public(metadata)

    def receiver_status(self, token: str) -> dict:
        with self._lock:
            self._cleanup_locked()
            metadata, _ = self._find_by_token_locked(token)
            return self._public(metadata)

    def read_chunk(self, *, token: str, relay_id: str, item_id: str, chunk_index: int) -> bytes:
        with self._lock:
            metadata, folder = self._find_by_token_locked(token)
            if metadata["relay_id"] != relay_id:
                raise P2PRelayError("Relay session not found", 404)
            if metadata["status"] != "ready":
                raise P2PRelayError("Relay payload is not ready", 409)
            item = self._item(metadata, item_id)
            if chunk_index < 0 or chunk_index >= item["chunk_count"]:
                raise P2PRelayError("Invalid relay chunk index")
            path = folder / "chunks" / item_id / f"{chunk_index:08d}.bin"
            try:
                data = path.read_bytes()
            except OSError:
                raise P2PRelayError("Relay chunk not found", 404) from None
            if len(data) != self._expected_cipher_chunk_size(item, chunk_index):
                raise P2PRelayError("Relay ciphertext is corrupt", 409)
            expected_hash = str((item.get("chunk_hashes") or {}).get(str(chunk_index), ""))
            if expected_hash and hashlib.sha256(data).hexdigest() != expected_hash:
                raise P2PRelayError("Relay ciphertext is corrupt", 409)
            return data

    def complete_download(self, token: str) -> None:
        with self._lock:
            metadata, folder = self._find_by_token_locked(token)
            metadata["status"] = "downloaded"
            metadata["updated_at"] = time.time()
            self._write_metadata(folder, metadata)
            shutil.rmtree(folder, ignore_errors=True)

    def discard(self, relay_id: str) -> None:
        if not _hex(relay_id, 32):
            return
        with self._lock:
            shutil.rmtree(self.root / relay_id, ignore_errors=True)

    def revoke(self, *, relay_id: str, owner: str) -> bool:
        with self._lock:
            try:
                metadata, folder = self._load_locked(relay_id)
            except P2PRelayError as error:
                if error.status == 404:
                    return False
                raise
            self._require_owner(metadata, owner)
            shutil.rmtree(folder, ignore_errors=True)
            return True

    def replica_write(self, *, relay_id: str, relative_path: str, data: bytes) -> None:
        """Apply an authenticated cluster replica write atomically.

        Replica traffic never contains E2E keys or bootstrap secrets; it is the
        same signed metadata/ciphertext already persisted by the relay store.
        """
        if not _hex(relay_id, 32):
            raise P2PRelayError("Invalid relay replica id")
        if len(data) > max(MAX_METADATA_BYTES, REPLICA_MAX_PAYLOAD_BYTES):
            raise P2PRelayError("Relay replica payload is too large", 413)
        relative = Path(str(relative_path))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise P2PRelayError("Invalid relay replica path")
        if relative.as_posix() != "relay.json":
            parts = relative.parts
            if len(parts) != 3 or parts[0] != "chunks" or not parts[2].endswith(".bin"):
                raise P2PRelayError("Invalid relay replica path")
        with self._lock:
            folder = self.root / relay_id
            target = folder / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(target.suffix + ".replica.tmp")
            try:
                with tmp.open("wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, target)
            except OSError as error:
                tmp.unlink(missing_ok=True)
                if error.errno in (errno.ENOSPC, errno.EDQUOT):
                    raise P2PRelayError("Relay replica storage is full", 507) from None
                raise

    def replica_delete(self, relay_id: str) -> None:
        if not _hex(relay_id, 32):
            raise P2PRelayError("Invalid relay replica id")
        with self._lock:
            shutil.rmtree(self.root / relay_id, ignore_errors=True)

    def replica_prune(self, active_relay_ids: list[str] | tuple[str, ...] | set[str]) -> None:
        allowed = {str(value) for value in active_relay_ids if _hex(str(value), 32)}
        with self._lock:
            if not self.root.exists():
                return
            for folder in list(self.root.iterdir()):
                if folder.is_dir() and _hex(folder.name, 32) and folder.name not in allowed:
                    shutil.rmtree(folder, ignore_errors=True)

    def replica_files(self) -> list[tuple[str, str, bytes]]:
        """Return a bounded snapshot source for reconnect synchronization."""
        values: list[tuple[str, str, bytes]] = []
        with self._lock:
            self._cleanup_locked()
            if not self.root.exists():
                return values
            for folder in sorted(self.root.iterdir(), key=lambda path: path.name):
                if not folder.is_dir() or not _hex(folder.name, 32):
                    continue
                metadata_path = folder / "relay.json"
                if metadata_path.exists():
                    values.append((folder.name, "relay.json", metadata_path.read_bytes()))
                chunks_root = folder / "chunks"
                if chunks_root.exists():
                    for path in sorted(chunks_root.rglob("*.bin")):
                        values.append((folder.name, path.relative_to(folder).as_posix(), path.read_bytes()))
        return values

    def _validate_items(self, items: list[dict], invitation_files: list[dict]) -> tuple[list[dict], int]:
        if not isinstance(items, list) or not items or len(items) > MAX_ITEMS:
            raise P2PRelayError(f"Relay must contain 1 to {MAX_ITEMS} items")
        invited = {str(item.get("id")): item for item in invitation_files if isinstance(item, dict)}
        if len(items) != len(invited):
            raise P2PRelayError("Relay manifest differs from invitation")
        normalized = []
        seen = set()
        total = 0
        clear_total = 0
        for raw in items:
            if not isinstance(raw, dict):
                raise P2PRelayError("Invalid relay item")
            item_id = str(raw.get("id", "")).strip()
            filename = str(raw.get("filename", "")).strip()
            try:
                clear_size = int(raw.get("clear_size"))
                chunk_count = int(raw.get("chunk_count"))
                ciphertext_size = int(raw.get("ciphertext_size"))
            except (TypeError, ValueError):
                raise P2PRelayError("Invalid relay item size") from None
            if not item_id or item_id in seen or len(item_id) > 80 or not item_id.replace("-", "").replace("_", "").isalnum():
                raise P2PRelayError("Invalid relay item id")
            if not filename or Path(filename).name != filename or filename in (".", ".."):
                raise P2PRelayError("Invalid relay filename")
            expected_chunks = max(1, (clear_size + CLEAR_CHUNK_SIZE - 1) // CLEAR_CHUNK_SIZE)
            expected_cipher = clear_size + expected_chunks * AES_GCM_ENVELOPE_OVERHEAD
            if clear_size < 0 or chunk_count != expected_chunks or ciphertext_size != expected_cipher:
                raise P2PRelayError("Invalid relay ciphertext sizing")
            invited_item = invited.get(item_id)
            if invited_item is None or str(invited_item.get("filename")) != filename or int(invited_item.get("size", -1)) != clear_size:
                raise P2PRelayError("Relay manifest differs from invitation")
            total += ciphertext_size
            clear_total += clear_size
            if clear_total > MAX_RELAY_CLEAR_BYTES:
                raise P2PRelayError("Relay transfer is too large", 413)
            seen.add(item_id)
            normalized.append({
                "id": item_id,
                "filename": filename,
                "clear_size": clear_size,
                "chunk_count": chunk_count,
                "ciphertext_size": ciphertext_size,
                "received_chunks": [],
                "chunk_hashes": {},
            })
        if seen != set(invited):
            raise P2PRelayError("Relay manifest differs from invitation")
        return normalized, total

    @staticmethod
    def _expected_cipher_chunk_size(item: dict, index: int) -> int:
        clear_size = int(item["clear_size"])
        offset = index * CLEAR_CHUNK_SIZE
        clear_len = max(0, min(CLEAR_CHUNK_SIZE, clear_size - offset))
        return clear_len + AES_GCM_ENVELOPE_OVERHEAD

    @staticmethod
    def _item(metadata: dict, item_id: str) -> dict:
        for item in metadata.get("items") or []:
            if item.get("id") == item_id:
                return item
        raise P2PRelayError("Relay item not found", 404)

    @staticmethod
    def _require_owner(metadata: dict, owner: str) -> None:
        if not owner or metadata.get("sender_owner") != owner:
            raise P2PRelayError("Relay session owner mismatch", 403)

    def _load_locked(self, relay_id: str) -> tuple[dict, Path]:
        if not _hex(relay_id, 32):
            raise P2PRelayError("Relay session not found", 404)
        folder = self.root / relay_id
        try:
            metadata = json.loads((folder / "relay.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise P2PRelayError("Relay session not found", 404) from None
        if float(metadata.get("expires_at", 0)) <= time.time():
            shutil.rmtree(folder, ignore_errors=True)
            raise P2PRelayError("Relay session expired", 410)
        return metadata, folder

    def _find_by_invitation_locked(self, invitation_id: str) -> tuple[dict, Path] | None:
        if not self.root.exists():
            return None
        for folder in self.root.iterdir():
            if not folder.is_dir():
                continue
            try:
                metadata = json.loads((folder / "relay.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if metadata.get("invitation_id") == invitation_id and float(metadata.get("expires_at", 0)) > time.time():
                return metadata, folder
        return None

    def _find_by_token_locked(self, token: str) -> tuple[dict, Path]:
        token_hash = _hash_token(token)
        if not token or not self.root.exists():
            raise P2PRelayError("Relay capability unavailable", 404)
        for folder in self.root.iterdir():
            if not folder.is_dir():
                continue
            try:
                metadata = json.loads((folder / "relay.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if metadata.get("receiver_token_hash") == token_hash:
                if float(metadata.get("expires_at", 0)) <= time.time():
                    shutil.rmtree(folder, ignore_errors=True)
                    break
                return metadata, folder
        raise P2PRelayError("Relay capability unavailable", 404)

    def _active_count_locked(self) -> int:
        if not self.root.exists():
            return 0
        return sum(1 for path in self.root.iterdir() if path.is_dir() and (path / "relay.json").exists())

    def _reserved_bytes_locked(self, *, exclude_relay_id: str | None = None) -> int:
        if not self.root.exists():
            return 0
        total = 0
        for folder in self.root.iterdir():
            if not folder.is_dir() or folder.name == exclude_relay_id:
                continue
            try:
                metadata = json.loads((folder / "relay.json").read_text(encoding="utf-8"))
                total += sum(int(item.get("ciphertext_size", 0)) for item in metadata.get("items") or [])
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return total

    def cleanup(self) -> None:
        with self._lock:
            self._cleanup_locked()

    def _cleanup_locked(self) -> None:
        if not self.root.exists():
            return
        now = time.time()
        for folder in list(self.root.iterdir()):
            if not folder.is_dir():
                continue
            try:
                metadata = json.loads((folder / "relay.json").read_text(encoding="utf-8"))
                expired = float(metadata.get("expires_at", 0)) <= now
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                expired = True
            if expired:
                shutil.rmtree(folder, ignore_errors=True)
                continue
            for tmp in folder.rglob("*.tmp"):
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass

    @staticmethod
    def _public(metadata: dict) -> dict:
        result = {key: value for key, value in metadata.items() if key not in ("receiver_token_hash", "sender_owner")}
        result["items"] = [
            {key: value for key, value in item.items() if key not in ("received_chunks", "chunk_hashes")}
            for item in metadata.get("items") or []
        ]
        if metadata.get("status") == "uploading":
            result["upload_progress"] = [
                {"id": item["id"], "received_chunks": list(item.get("received_chunks") or [])}
                for item in metadata.get("items") or []
            ]
        return result

    @staticmethod
    def _write_metadata(folder: Path, metadata: dict) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(metadata, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_METADATA_BYTES:
            raise P2PRelayError("Relay metadata is too large", 413)
        tmp = folder / "relay.json.tmp"
        with tmp.open("wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, folder / "relay.json")


def _hash_token(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def _hex(value: str, length: int) -> bool:
    return len(value) == length and all(char in "0123456789abcdef" for char in value)
