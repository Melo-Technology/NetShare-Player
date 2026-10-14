"""Bounded, one-time web download tickets and short-lived Range grants."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

TICKET_PREFIX = "nwd_"
TICKET_TTL_SECONDS = 30
GRANT_TTL_SECONDS = 5 * 60
GRANT_MAX_REQUESTS = 8
MAX_TICKETS = 1000
MAX_ACTIVE_STREAMS = 3


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class DownloadGrant:
    token_hash: str
    session_id: str
    generation: int
    path: str
    etag: str
    size: int
    ticket_expires_at: float
    grant_expires_at: float | None = None
    requests: int = 0


@dataclass(frozen=True)
class DownloadAuthorization:
    status: str
    grant: DownloadGrant | None = None


class WebDownloadTicketStore:
    def __init__(
        self, *, clock: Callable[[], float] = time.time, maximum: int = MAX_TICKETS
    ):
        self.clock = clock
        self.maximum = maximum
        self._lock = threading.RLock()
        self._tickets: dict[str, DownloadGrant] = {}
        self._active: dict[str, int] = {}

    def _cleanup_locked(self, now: float) -> None:
        expired = [
            key for key, item in self._tickets.items()
            if (item.grant_expires_at or item.ticket_expires_at) < now
        ]
        for key in expired:
            self._tickets.pop(key, None)

    def issue(
        self, *, session_id: str, generation: int, path: str, etag: str, size: int
    ) -> tuple[str, DownloadGrant]:
        now = self.clock()
        token = TICKET_PREFIX + secrets.token_urlsafe(24)
        grant = DownloadGrant(
            token_hash=_hash_token(token), session_id=session_id,
            generation=generation, path=path, etag=etag, size=size,
            ticket_expires_at=now + TICKET_TTL_SECONDS,
        )
        with self._lock:
            self._cleanup_locked(now)
            if len(self._tickets) >= self.maximum:
                oldest = min(
                    self._tickets,
                    key=lambda key: self._tickets[key].grant_expires_at
                    or self._tickets[key].ticket_expires_at,
                )
                self._tickets.pop(oldest, None)
            self._tickets[grant.token_hash] = grant
        return token, grant

    def authorize(
        self, token: str, *, generation: int,
        session_active: Callable[[str], bool],
    ) -> DownloadAuthorization:
        now = self.clock()
        with self._lock:
            grant = self._tickets.get(_hash_token(token))
            if grant is None:
                return DownloadAuthorization("invalid")
            expiry = grant.grant_expires_at or grant.ticket_expires_at
            if expiry < now:
                self._tickets.pop(grant.token_hash, None)
                return DownloadAuthorization("expired")
            if grant.generation != generation or not session_active(grant.session_id):
                self._tickets.pop(grant.token_hash, None)
                return DownloadAuthorization("invalid")
            if grant.grant_expires_at is None:
                grant.grant_expires_at = now + GRANT_TTL_SECONDS
            if grant.requests >= GRANT_MAX_REQUESTS:
                return DownloadAuthorization("exhausted")
            grant.requests += 1
            return DownloadAuthorization("valid", grant)

    def acquire_stream(self, session_id: str) -> bool:
        with self._lock:
            active = self._active.get(session_id, 0)
            if active >= MAX_ACTIVE_STREAMS:
                return False
            self._active[session_id] = active + 1
            return True

    def release_stream(self, session_id: str) -> None:
        with self._lock:
            active = self._active.get(session_id, 0)
            if active <= 1:
                self._active.pop(session_id, None)
            else:
                self._active[session_id] = active - 1

    def revoke_session(self, session_id: str) -> int:
        with self._lock:
            keys = [key for key, item in self._tickets.items() if item.session_id == session_id]
            for key in keys:
                self._tickets.pop(key, None)
            return len(keys)

    def active_stream_count(self) -> int:
        with self._lock:
            return sum(int(value) for value in self._active.values())

    def clear(self) -> dict[str, int]:
        with self._lock:
            tickets = len(self._tickets)
            active = self.active_stream_count()
            if active:
                raise RuntimeError("web download stream is active")
            self._tickets.clear()
            self._active.clear()
            return {"tickets": tickets, "active_streams": active}
