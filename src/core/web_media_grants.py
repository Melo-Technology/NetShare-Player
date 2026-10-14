"""Short-lived, session-bound capability URLs for browser media playback."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

MEDIA_GRANT_PREFIX = "nwm_"
MEDIA_GRANT_TTL_SECONDS = 15 * 60
MEDIA_GRANT_MAX_REQUESTS = 128
MAX_MEDIA_GRANTS = 1000


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class MediaGrant:
    token_hash: str
    session_id: str
    generation: int
    path: str
    origin: str
    etag: str
    size: int
    expires_at: float
    requests: int = 0


class WebMediaGrantStore:
    def __init__(self, *, clock: Callable[[], float] = time.time):
        self.clock = clock
        self._lock = threading.RLock()
        self._grants: dict[str, MediaGrant] = {}

    def issue(self, *, session_id: str, generation: int, path: str,
              origin: str, etag: str, size: int) -> tuple[str, MediaGrant]:
        now = self.clock()
        token = MEDIA_GRANT_PREFIX + secrets.token_urlsafe(24)
        grant = MediaGrant(
            token_hash=_hash_token(token), session_id=session_id,
            generation=generation, path=path, origin=origin, etag=etag,
            size=size, expires_at=now + MEDIA_GRANT_TTL_SECONDS,
        )
        with self._lock:
            self._cleanup(now)
            if len(self._grants) >= MAX_MEDIA_GRANTS:
                oldest = min(self._grants, key=lambda key: self._grants[key].expires_at)
                self._grants.pop(oldest, None)
            self._grants[grant.token_hash] = grant
        return token, grant

    def authorize(self, token: str, *, generation: int, origin: str,
                  session_active: Callable[[str], bool]) -> MediaGrant | None:
        now = self.clock()
        with self._lock:
            grant = self._grants.get(_hash_token(token))
            if grant is None:
                return None
            if (grant.expires_at < now or grant.generation != generation
                    or grant.origin != origin
                    or not session_active(grant.session_id)
                    or grant.requests >= MEDIA_GRANT_MAX_REQUESTS):
                self._grants.pop(grant.token_hash, None)
                return None
            grant.requests += 1
            return grant

    def _cleanup(self, now: float) -> None:
        for key in [key for key, grant in self._grants.items()
                    if grant.expires_at < now]:
            self._grants.pop(key, None)


    def clear(self) -> int:
        with self._lock:
            count = len(self._grants)
            self._grants.clear()
            return count

