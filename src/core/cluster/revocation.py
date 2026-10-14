"""Bounded local ticket replay and revocation state."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

MAX_TICKET_RECORDS = 4096
TICKET_RETENTION_GRACE_SECONDS = 5


class RevocationCapacityError(RuntimeError):
    """Raised when accepting another ticket would weaken replay protection."""


class RevocationStateError(RuntimeError):
    """Raised when persisted security state cannot be trusted."""


class RevocationRegistry:
    def __init__(self, path: Path | None = None, clock=time.time):
        self.path = path
        self.clock = clock
        self._lock = threading.RLock()
        self._generations: dict[str, int] = {}
        self._revoked: dict[str, int] = {}
        self._consumed: dict[str, int] = {}
        self._load()

    def current_generation(self, node_id: str) -> int:
        with self._lock:
            return self._generations.get(node_id, 0)

    def revoke_node(self, node_id: str) -> int:
        with self._lock:
            generation = self._generations.get(node_id, 0) + 1
            self._generations[node_id] = generation
            self._save()
            return generation

    def synchronize_generation(self, node_id: str, generation: int) -> None:
        """Install a generation without ever permitting a security rollback."""
        value = max(0, int(generation))
        with self._lock:
            current = self._generations.get(node_id, 0)
            if value < current:
                raise RevocationStateError("revocation generation cannot decrease")
            self._generations[node_id] = value
            self._save()

    def merge_generations(self, generations: dict[str, int]) -> dict[str, int]:
        """Monotonically merge authenticated generation state.

        Failover replicas and authenticated heartbeats may carry a generation
        snapshot that is older than the local persisted registry.  In that
        case the local value wins; a remote snapshot is never allowed to roll
        revocation state backwards.
        """
        if not isinstance(generations, dict):
            raise RevocationStateError("revocation generations must be a mapping")
        changed = False
        with self._lock:
            for raw_node_id, raw_generation in generations.items():
                node_id = str(raw_node_id)[:128]
                if not node_id:
                    continue
                try:
                    generation = max(0, int(raw_generation))
                except (TypeError, ValueError) as error:
                    raise RevocationStateError("invalid revocation generation") from error
                current = self._generations.get(node_id, 0)
                if generation > current:
                    self._generations[node_id] = generation
                    changed = True
            if changed:
                self._save()
            return dict(self._generations)

    def generation_snapshot(self, node_ids=None) -> dict[str, int]:
        """Return a bounded copy of current per-node ticket generations."""
        with self._lock:
            if node_ids is None:
                return dict(self._generations)
            result = {}
            for raw_node_id in node_ids:
                node_id = str(raw_node_id)
                if node_id:
                    result[node_id] = self._generations.get(node_id, 0)
            return result

    def revoke_ticket(self, ticket_id: str, expires_at: int) -> None:
        with self._lock:
            self._purge()
            if ticket_id not in self._revoked and ticket_id not in self._consumed:
                self._require_capacity()
            self._consumed.pop(ticket_id, None)
            self._revoked[ticket_id] = int(expires_at) + TICKET_RETENTION_GRACE_SECONDS
            self._save()

    def consume(self, ticket_id: str, expires_at: int) -> bool:
        with self._lock:
            self._purge()
            if ticket_id in self._revoked or ticket_id in self._consumed:
                return False
            self._require_capacity()
            self._consumed[ticket_id] = int(expires_at) + TICKET_RETENTION_GRACE_SECONDS
            self._save()
            return True

    def is_ticket_blocked(self, ticket_id: str) -> bool:
        with self._lock:
            self._purge()
            return ticket_id in self._revoked or ticket_id in self._consumed

    def is_ticket_revoked(self, ticket_id: str) -> bool:
        with self._lock:
            self._purge()
            return ticket_id in self._revoked

    def _purge(self) -> None:
        now = int(self.clock())
        self._revoked = {
            key: expiry for key, expiry in self._revoked.items() if expiry >= now
        }
        self._consumed = {
            key: expiry for key, expiry in self._consumed.items() if expiry >= now
        }

    def _require_capacity(self) -> None:
        if len(self._revoked) + len(self._consumed) >= MAX_TICKET_RECORDS:
            raise RevocationCapacityError("ticket replay cache is full")

    def _load(self) -> None:
        if self.path is None:
            return
        if not self.path.exists():
            return
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            self._generations = {str(k): max(0, int(v)) for k, v in dict(value.get("generations", {})).items()}
            self._revoked = {
                str(k): int(v) for k, v in dict(value.get("revoked", {})).items()
            }
            self._consumed = {
                str(k): int(v) for k, v in dict(value.get("consumed", {})).items()
            }
            self._purge()
            if len(self._revoked) + len(self._consumed) > MAX_TICKET_RECORDS:
                raise RevocationStateError("ticket replay cache exceeds its bound")
        except RevocationStateError:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise RevocationStateError("persisted revocation state is invalid") from error

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(
            {
                "generations": self._generations,
                "revoked": self._revoked,
                "consumed": self._consumed,
            },
            separators=(",", ":"), sort_keys=True,
        ), encoding="utf-8")
        temporary.replace(self.path)
