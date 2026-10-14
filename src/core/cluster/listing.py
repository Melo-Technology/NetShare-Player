"""Non-recursive, bounded cluster directory pages with sealed cursors."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from src.core import unlock_codes
from src.core.content_policy import visible_shared_entry
from src.core.media_analysis import is_audio
from src.core.shared_paths import encode_shared_path
from src.utils.network import file_info

CURSOR_TTL_SECONDS = 120
MAX_LIST_LIMIT = 100
MAX_DIRECTORY_ENTRIES = 10_000
MAX_LIST_RESPONSE_BYTES = 256 * 1024


class ListingError(ValueError):
    pass


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True,
        )
    except (ValueError, TypeError) as error:
        raise ListingError("invalid listing cursor") from error


@dataclass(frozen=True)
class ListingPage:
    items: tuple[dict, ...]
    next_cursor: str


class ListingCursorCodec:
    def __init__(self, private_key, *, node_id: str, clock=time.time):
        self._private = private_key
        self._public = private_key.public_key()
        self.node_id = node_id
        self.clock = clock

    @classmethod
    def from_private_bytes(cls, value: bytes, *, node_id: str, clock=time.time):
        return cls(Ed25519PrivateKey.from_private_bytes(value), node_id=node_id, clock=clock)

    def encode(
        self, *, path: str, after: str, limit: int, snapshot: str,
    ) -> str:
        payload = json.dumps({
            "v": 1, "node": self.node_id, "path": path,
            "after": after, "limit": int(limit), "snapshot": snapshot,
            "exp": int(self.clock()) + CURSOR_TTL_SECONDS,
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return f"nsc1.{_b64(payload)}.{_b64(self._private.sign(payload))}"

    def decode(
        self, cursor: str, *, path: str, limit: int, snapshot: str,
    ) -> str:
        try:
            prefix, payload_text, signature_text = str(cursor).split(".")
            if prefix != "nsc1":
                raise ListingError("invalid listing cursor")
            payload = _unb64(payload_text)
            self._public.verify(_unb64(signature_text), payload)
            value = json.loads(payload.decode("utf-8"))
            if (
                value.get("v") != 1
                or value.get("node") != self.node_id
                or value.get("path") != path
                or int(value.get("limit", 0)) != int(limit)
                or value.get("snapshot") != snapshot
                or int(value.get("exp", 0)) < int(self.clock())
            ):
                raise ListingError("listing cursor does not match request")
            return str(value.get("after") or "")
        except ListingError:
            raise
        except (InvalidSignature, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
            raise ListingError("invalid listing cursor") from error


def directory_snapshot(entries: list[tuple[str, Path]]) -> str:
    """Hash (slot, entry) pairs so a merged multiroot listing gets its own snapshot."""
    digest = hashlib.sha256()
    for slot, entry in entries:
        try:
            stat = entry.stat()
        except OSError as error:
            raise ListingError("directory changed during listing") from error
        digest.update(slot.encode("ascii"))
        digest.update(b"\0")
        digest.update(entry.name.encode("utf-8", errors="strict"))
        digest.update(b"\0d\0" if entry.is_dir() else b"\0f\0")
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def list_directory_page(
    *, roots: tuple[tuple[str, Path, Path], ...], path: str, limit: int, cursor: str,
    codec: ListingCursorCodec, device_id: str = "",
) -> ListingPage:
    """List one directory, or merge several (slot, root_path, directory) triples
    into a single flattened page — used when `path` is the virtual root "/" and
    the Slave exposes more than one shared root (slot-1 + slot-2)."""
    if not 1 <= int(limit) <= MAX_LIST_LIMIT:
        raise ListingError("invalid listing limit")
    multi = len(roots) > 1
    combined: list[tuple[str, Path, Path]] = []  # (slot, root_path, entry)
    try:
        for slot, root_path, directory in roots:
            for entry in directory.iterdir():
                if visible_shared_entry(entry, root=root_path, slot=slot):
                    combined.append((slot, root_path, entry))
    except OSError as error:
        raise ListingError("directory cannot be listed") from error
    if len(combined) > MAX_DIRECTORY_ENTRIES:
        raise ListingError("directory listing exceeds local safety bound")
    combined.sort(key=lambda item: (not item[2].is_dir(), item[2].name.casefold(), item[2].name, item[0]))
    snapshot = directory_snapshot([(slot, entry) for slot, _root, entry in combined])
    after = codec.decode(cursor, path=path, limit=limit, snapshot=snapshot) if cursor else ""
    start = 0
    if after:
        after_slot, _, after_name = after.partition("\0")
        matches = [
            index for index, (slot, _root, entry) in enumerate(combined)
            if entry.name == (after_name or after) and (not multi or slot == after_slot)
        ]
        if len(matches) != 1:
            raise ListingError("listing cursor position is unavailable")
        start = matches[0] + 1
    selected = combined[start:start + limit]
    items = []
    for slot, root_path, entry in selected:
        relative = "/" + entry.relative_to(root_path).as_posix()
        public_path = encode_shared_path(slot, relative) if multi else relative
        lock = unlock_codes.lock_status_for_path(public_path, device_id)
        premium = unlock_codes.find_governing_premium_folder(public_path) is not None
        info = file_info(entry, root_path)
        info["path"] = public_path
        info["modified_ns"] = entry.stat().st_mtime_ns
        info["premium"] = premium
        info["locked"] = lock["locked"]
        if entry.is_file() and is_audio(entry):
            from src.core.file_index import _file_index
            # NOTE: browse.py calls loudness_gain/bpm with (path, root_slot);
            # verify _file_index's signature matches before shipping this.
            info["loudness_gain"] = _file_index.loudness_gain(public_path, slot)
            info["bpm"] = _file_index.bpm(public_path, slot)
        items.append(info)
    next_cursor = ""
    if start + len(selected) < len(combined) and selected:
        last_slot, _root, last_entry = selected[-1]
        after_value = f"{last_slot}\0{last_entry.name}" if multi else last_entry.name
        next_cursor = codec.encode(
            path=path, after=after_value, limit=limit, snapshot=snapshot,
        )
    encoded_size = len(json.dumps(
        {"items": items, "next_cursor": next_cursor},
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8"))
    if encoded_size > MAX_LIST_RESPONSE_BYTES:
        raise ListingError("listing response exceeds safety bound")
    return ListingPage(tuple(items), next_cursor)