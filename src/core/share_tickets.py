"""Short-lived, scope-bound share tickets stored only as token hashes."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass


MAX_TICKETS = 128
MAX_PATHS = 50
MAX_TTL_SECONDS = 24 * 60 * 60
MAX_ACCESSES = 100


class ShareTicketError(Exception):
    pass


@dataclass(frozen=True)
class TicketGrant:
    ticket_id: str
    paths: tuple[str, ...]
    allow_download: bool
    scope: str
    expires_at: float
    remaining_accesses: int


class ShareTicketStore:
    def __init__(self):
        self._tickets: dict[str, dict] = {}
        self._lock = threading.RLock()

    def create(self, paths: list[str], ttl_seconds: int, max_accesses: int, allow_download: bool, scope: str) -> dict:
        normalized = self._validate(paths, ttl_seconds, max_accesses, scope)
        token = secrets.token_urlsafe(32)
        token_hash = self._hash(token)
        now = time.time()
        with self._lock:
            self._cleanup(now)
            if len(self._tickets) >= MAX_TICKETS:
                oldest = min(self._tickets, key=lambda key: self._tickets[key]["created_at"])
                del self._tickets[oldest]
            ticket_id = secrets.token_hex(8)
            self._tickets[token_hash] = {
                "id": ticket_id,
                "paths": normalized,
                "allow_download": bool(allow_download),
                "scope": scope,
                "created_at": now,
                "expires_at": now + ttl_seconds,
                "remaining_accesses": max_accesses,
                "revoked": False,
            }
        return {"id": ticket_id, "token": token, "scope": scope, "expires_at": now + ttl_seconds, "remaining_accesses": max_accesses}

    def consume(self, token: str, scope: str) -> TicketGrant | None:
        with self._lock:
            self._cleanup(time.time())
            record = self._tickets.get(self._hash(token))
            if not record or record["revoked"] or record["scope"] != scope or record["remaining_accesses"] <= 0:
                return None
            record["remaining_accesses"] -= 1
            return self._grant(record)

    def inspect(self, token: str, scope: str) -> TicketGrant | None:
        with self._lock:
            self._cleanup(time.time())
            record = self._tickets.get(self._hash(token))
            if (
                not record
                or record["revoked"]
                or record["scope"] != scope
                or record["remaining_accesses"] <= 0
            ):
                return None
            return self._grant(record)

    def revoke(self, ticket_id: str) -> bool:
        with self._lock:
            for record in self._tickets.values():
                if record["id"] == ticket_id:
                    record["revoked"] = True
                    return True
        return False

    def revoke_paths(self, slot: str, hidden_path: str) -> list[str]:
        """Revoke active grants whose configured path is hidden recursively."""
        from src.core.shared_paths import parse_shared_path
        prefix = "/" + str(hidden_path).strip("/")
        revoked = []
        with self._lock:
            for record in self._tickets.values():
                for value in record["paths"]:
                    parsed = parse_shared_path(value)
                    if parsed is None:
                        continue
                    path_slot, relative = parsed
                    normalized = "/" + str(relative).strip("/")
                    if path_slot == slot and (normalized == prefix or normalized.startswith(prefix + "/")):
                        record["revoked"] = True
                        revoked.append(record["id"])
                        break
        return revoked

    @staticmethod
    def _validate(paths: list[str], ttl_seconds: int, max_accesses: int, scope: str) -> tuple[str, ...]:
        if not isinstance(paths, list) or not paths or len(paths) > MAX_PATHS:
            raise ShareTicketError(f"Share must contain 1 to {MAX_PATHS} paths")
        if scope not in ("lan", "tunnel"):
            raise ShareTicketError("Invalid ticket scope")
        if not 60 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ShareTicketError("Invalid ticket lifetime")
        if not 1 <= max_accesses <= MAX_ACCESSES:
            raise ShareTicketError("Invalid access limit")
        normalized = []
        for value in paths:
            path = str(value).strip().replace("\\", "/")
            if not path.startswith("/") or ".." in path.split("/"):
                raise ShareTicketError("Invalid shared path")
            normalized.append(path)
        return tuple(dict.fromkeys(normalized))

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _grant(record: dict) -> TicketGrant:
        return TicketGrant(record["id"], record["paths"], record["allow_download"], record["scope"], record["expires_at"], record["remaining_accesses"])

    def _cleanup(self, now: float) -> None:
        expired = [key for key, value in self._tickets.items() if value["expires_at"] <= now or value["revoked"]]
        for key in expired:
            del self._tickets[key]


share_ticket_store = ShareTicketStore()
