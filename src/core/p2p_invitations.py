"""Ephemeral Player-to-Player invitation registry (metadata only, no file bytes)."""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass

MAX_INVITATIONS = 128
MIN_TTL_SECONDS = 30
MAX_TTL_SECONDS = 15 * 60
MAX_ACCESSES = 3
MAX_ENVELOPE_BYTES = 64 * 1024


class P2PInvitationError(Exception):
    pass


@dataclass(frozen=True)
class P2PInvitationGrant:
    invitation_id: str
    envelope: dict
    expires_at: float
    remaining_accesses: int
    resolved_at: float | None = None
    resolve_count: int = 0


class P2PInvitationStore:
    def __init__(self):
        self._records: dict[str, dict] = {}
        self._lock = threading.RLock()

    def create(self, envelope: dict, ttl_seconds: int, max_accesses: int) -> dict:
        if not isinstance(envelope, dict):
            raise P2PInvitationError("Invalid invitation envelope")
        if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
            raise P2PInvitationError("Invalid invitation lifetime")
        if not 1 <= max_accesses <= MAX_ACCESSES:
            raise P2PInvitationError("Invalid invitation access limit")
        invite_id = str(envelope.get("invite_id", "")).strip()
        if len(invite_id) != 32 or any(c not in "0123456789abcdef" for c in invite_id):
            raise P2PInvitationError("Invalid invitation id")
        if envelope.get("protocol") != "NSP2P-INVITE" or envelope.get("version") != 1:
            raise P2PInvitationError("Unsupported invitation protocol")

        token = secrets.token_urlsafe(32)
        token_hash = self._hash(token)
        now = time.time()
        expires_at = now + ttl_seconds
        with self._lock:
            self._cleanup(now)
            # A signed invitation id represents one logical invitation. Replace
            # stale same-id records so sender status can never resolve to an
            # older in-memory entry during hot-reload/dev test cycles.
            for key, value in list(self._records.items()):
                if value.get("id") == invite_id:
                    del self._records[key]
            if len(self._records) >= MAX_INVITATIONS:
                oldest = min(self._records, key=lambda key: self._records[key]["created_at"])
                del self._records[oldest]
            self._records[token_hash] = {
                "id": invite_id,
                "envelope": envelope,
                "created_at": now,
                "expires_at": expires_at,
                "remaining_accesses": max_accesses,
                "resolved_at": None,
                "resolve_count": 0,
                "revoked": False,
            }
        return {
            "id": invite_id,
            "token": token,
            "expires_at": expires_at,
            "remaining_accesses": max_accesses,
        }

    def inspect(self, token: str) -> P2PInvitationGrant | None:
        with self._lock:
            self._cleanup(time.time())
            record = self._records.get(self._hash(token))
            if not record or record["revoked"] or record["remaining_accesses"] <= 0:
                return None
            return self._grant(record)

    def resolve(self, token: str) -> P2PInvitationGrant | None:
        """Resolve an invitation capability and mark it as observed by a receiver.

        Resolution does not consume an access.  It only records the first
        successful metadata lookup so the sender UI can dismiss the QR sheet
        once another Player has actually scanned/pasted the invitation.
        """
        with self._lock:
            now = time.time()
            self._cleanup(now)
            record = self._records.get(self._hash(token))
            if not record or record["revoked"] or record["remaining_accesses"] <= 0:
                return None
            if record.get("resolved_at") is None:
                record["resolved_at"] = now
            record["resolve_count"] = int(record.get("resolve_count") or 0) + 1
            return self._grant(record)

    def sender_status(self, invitation_id: str) -> dict | None:
        """Return metadata-only observation state for the authenticated sender."""
        with self._lock:
            self._cleanup(time.time())
            for record in self._records.values():
                if record["id"] != invitation_id or record["revoked"]:
                    continue
                return {
                    "id": record["id"],
                    "resolved": record.get("resolved_at") is not None,
                    "resolved_at": record.get("resolved_at"),
                    "resolve_count": int(record.get("resolve_count") or 0),
                    "expires_at": record["expires_at"],
                    "remaining_accesses": record["remaining_accesses"],
                }
        return None

    def consume(self, token: str, expected_invitation_id: str) -> P2PInvitationGrant | None:
        with self._lock:
            self._cleanup(time.time())
            record = self._records.get(self._hash(token))
            if (
                not record
                or record["revoked"]
                or record["remaining_accesses"] <= 0
                or record["id"] != expected_invitation_id
            ):
                return None
            record["remaining_accesses"] -= 1
            return self._grant(record)

    def revoke(self, invitation_id: str) -> bool:
        with self._lock:
            for record in self._records.values():
                if record["id"] == invitation_id:
                    record["revoked"] = True
                    return True
        return False

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _grant(record: dict) -> P2PInvitationGrant:
        return P2PInvitationGrant(
            record["id"],
            record["envelope"],
            record["expires_at"],
            record["remaining_accesses"],
            record.get("resolved_at"),
            int(record.get("resolve_count") or 0),
        )

    def _cleanup(self, now: float) -> None:
        stale = [
            key for key, value in self._records.items()
            if value["expires_at"] <= now or value["revoked"]
        ]
        for key in stale:
            del self._records[key]


p2p_invitation_store = P2PInvitationStore()
