"""Persistent guest profiles and ephemeral, separately-authenticated sessions."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from src.core.content_policy import normalize_relative_path
from src.core.shared_roots import ROOT_SLOTS
from src.core.vault_storage import read_json, write_json


MAX_PROFILES = 32
MAX_PATHS = 64
SESSION_TTL_SECONDS = 8 * 60 * 60
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class GuestProfileError(ValueError):
    pass


@dataclass(frozen=True)
class GuestSession:
    profile_id: str
    profile_name: str
    allowed_paths: tuple[tuple[str, str], ...]
    expires_at: float


class GuestProfileStore:
    def __init__(self, path: Path, *, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self._lock = threading.RLock()
        self._profiles = self._load()
        self._sessions: dict[str, dict] = {}

    def create(self, name: str, allowed_paths: list[dict]) -> dict:
        clean_name = str(name or "").strip()
        if not clean_name or len(clean_name) > 80:
            raise GuestProfileError("Invalid guest profile name")
        normalized = self._normalize_paths(allowed_paths)
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(10))
        profile_id = secrets.token_hex(8)
        record = {
            "id": profile_id,
            "name": clean_name,
            "code_hash": self._hash(code),
            "generation": 1,
            "allowed_paths": [
                {"root_slot": slot, "path": path} for slot, path in normalized
            ],
            "created_at": self.clock(),
        }
        with self._lock:
            if len(self._profiles) >= MAX_PROFILES:
                raise GuestProfileError("Guest profile limit reached")
            self._profiles[profile_id] = record
            self._save()
        return {**self._public(record), "code": code}

    def list(self) -> list[dict]:
        with self._lock:
            return [self._public(record) for record in self._profiles.values()]

    def revoke(self, profile_id: str) -> bool:
        with self._lock:
            removed = self._profiles.pop(str(profile_id), None)
            if removed is None:
                return False
            self._sessions = {
                key: value for key, value in self._sessions.items()
                if value["profile_id"] != profile_id
            }
            self._save()
            return True

    def exchange_code(self, code: str) -> dict | None:
        received_hash = self._hash(str(code or "").strip().upper())
        now = self.clock()
        with self._lock:
            profile = next(
                (
                    record for record in self._profiles.values()
                    if hmac.compare_digest(record["code_hash"], received_hash)
                ),
                None,
            )
            if profile is None:
                return None
            token = secrets.token_urlsafe(32)
            expires_at = now + SESSION_TTL_SECONDS
            self._sessions[self._hash(token)] = {
                "profile_id": profile["id"],
                "generation": profile["generation"],
                "expires_at": expires_at,
            }
            return {
                "guest_session": token,
                "profile": self._public(profile),
                "expires_at": expires_at,
            }

    def verify_session(self, token: str) -> GuestSession | None:
        if not token:
            return None
        now = self.clock()
        token_hash = self._hash(token)
        with self._lock:
            session = self._sessions.get(token_hash)
            if session is None or session["expires_at"] <= now:
                self._sessions.pop(token_hash, None)
                return None
            profile = self._profiles.get(session["profile_id"])
            if profile is None or profile["generation"] != session["generation"]:
                self._sessions.pop(token_hash, None)
                return None
            allowed = tuple(
                (item["root_slot"], item["path"])
                for item in profile["allowed_paths"]
            )
            return GuestSession(
                profile["id"], profile["name"], allowed, session["expires_at"],
            )

    @staticmethod
    def _normalize_paths(values: list[dict]) -> tuple[tuple[str, str], ...]:
        if not isinstance(values, list) or not values or len(values) > MAX_PATHS:
            raise GuestProfileError(f"Profile must contain 1 to {MAX_PATHS} paths")
        result = []
        for item in values:
            if not isinstance(item, dict):
                raise GuestProfileError("Invalid guest path")
            slot = str(item.get("root_slot", "")).strip()
            path = normalize_relative_path(str(item.get("path", "")))
            if slot not in ROOT_SLOTS or ".." in path.split("/"):
                raise GuestProfileError("Invalid guest path")
            result.append((slot, path))
        return tuple(dict.fromkeys(result))

    def _load(self) -> dict[str, dict]:
        value = read_json(self.path, purpose="guest-profiles", default={})
        try:
            profiles = value.get("profiles", []) if isinstance(value, dict) else []
            return {
                item["id"]: item for item in profiles
                if isinstance(item, dict) and item.get("id") and item.get("code_hash")
            }
        except (TypeError, KeyError):
            return {}

    def _save(self) -> None:
        payload = {"schema": 1, "profiles": list(self._profiles.values())}
        write_json(self.path, payload, purpose="guest-profiles", indent=2)

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _public(record: dict) -> dict:
        return {
            "id": record["id"],
            "name": record["name"],
            "allowed_paths": [dict(item) for item in record["allowed_paths"]],
            "created_at": record["created_at"],
        }


_stores: dict[Path, GuestProfileStore] = {}
_stores_lock = threading.Lock()


def get_guest_profile_store(path: Path) -> GuestProfileStore:
    resolved = Path(path).resolve()
    with _stores_lock:
        return _stores.setdefault(resolved, GuestProfileStore(resolved))
