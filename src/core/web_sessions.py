"""Persistent, bounded web read-only sessions with opaque bearer tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from src.core.data_vault import VaultLockedError, get_data_vault, secure_unlink
from src.core.vault_storage import read_bytes, write_bytes

SESSION_PREFIX = "nws_"
MAX_SESSIONS = 100
IDLE_SECONDS = 30 * 60
ABSOLUTE_SECONDS = 12 * 60 * 60
TOUCH_INTERVAL_SECONDS = 60


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def rfc3339(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class WebSession:
    id: str
    role: str
    generation: int
    created_at: float
    last_seen_at: float
    expires_at: float
    idle_expires_at: float
    browser_family: str = "unknown"
    os_family: str = "unknown"

    def public_dict(self, *, include_client: bool = False) -> dict:
        payload = {
            "id": self.id,
            "role": self.role,
            "created_at": rfc3339(self.created_at),
            "expires_at": rfc3339(self.expires_at),
            "idle_expires_at": rfc3339(self.idle_expires_at),
        }
        if include_client:
            payload["last_seen_at"] = rfc3339(self.last_seen_at)
            payload["client"] = {
                "browser_family": self.browser_family,
                "os_family": self.os_family,
            }
        return payload


@dataclass(frozen=True)
class SessionLookup:
    status: str
    session: WebSession | None = None


class SessionCapacityError(RuntimeError):
    pass


class WebSessionStore:
    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        generation: Callable[[], int] = lambda: 1,
        maximum: int = MAX_SESSIONS,
    ):
        self.path = Path(path)
        self.clock = clock
        self.generation = generation
        self.maximum = maximum
        self._lock = threading.RLock()
        self._initialized = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # A password-protected vault is intentionally allowed to be locked at
        # process startup so the desktop can open and present the unlock UI.
        # Do not turn that expected state into an import-time crash. The schema
        # is initialized lazily after the vault has been unlocked.
        try:
            self._initialize()
        except VaultLockedError:
            pass

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        with self._lock:
            if not self._initialized:
                self._initialize()

    @contextmanager
    def _connect(self, *, ensure_initialized: bool = True):
        if ensure_initialized:
            self._ensure_initialized()
        import src.state as state
        vault = get_data_vault(state._CONFIG_DIR)
        encrypted = bool(vault.configured)
        connection = sqlite3.connect(":memory:" if encrypted else self.path, timeout=10)
        try:
            if encrypted and self.path.exists():
                raw = read_bytes(self.path, purpose="web-sessions-db")
                if raw:
                    connection.deserialize(raw)
            connection.row_factory = sqlite3.Row
            if not encrypted:
                connection.execute("PRAGMA journal_mode=WAL")
            yield connection
            connection.commit()
            if encrypted:
                write_bytes(self.path, connection.serialize(), purpose="web-sessions-db")
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self):
        with self._connect(ensure_initialized=False) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS web_sessions (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    last_seen_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL,
                    browser_family TEXT NOT NULL,
                    os_family TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_web_sessions_token
                    ON web_sessions(token_hash);
                CREATE INDEX IF NOT EXISTS idx_web_sessions_expiry
                    ON web_sessions(expires_at, last_seen_at);
                """
            )
        self._initialized = True

    def cleanup(self) -> int:
        now = self.clock()
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM web_sessions WHERE expires_at < ? OR last_seen_at + ? < ?",
                (now, IDLE_SECONDS, now),
            )
            return cursor.rowcount

    def create(self, *, browser_family="unknown", os_family="unknown") -> tuple[WebSession, str]:
        now = self.clock()
        session_id = SESSION_PREFIX + secrets.token_urlsafe(18)
        token = secrets.token_urlsafe(32)
        generation = int(self.generation())
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM web_sessions WHERE expires_at < ? OR last_seen_at + ? < ?",
                (now, IDLE_SECONDS, now),
            )
            count = connection.execute(
                "SELECT COUNT(*) FROM web_sessions WHERE revoked_at IS NULL"
            ).fetchone()[0]
            if count >= self.maximum:
                raise SessionCapacityError("web session capacity reached")
            connection.execute(
                "INSERT INTO web_sessions VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                (
                    session_id, _hash_token(token), "web_read_only", generation,
                    now, now, now + ABSOLUTE_SECONDS,
                    str(browser_family)[:64], str(os_family)[:64],
                ),
            )
        return self._lookup_by_id(session_id), token

    def _lookup_by_id(self, session_id: str) -> WebSession:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM web_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        if row is None:
            raise KeyError(session_id)
        return self._row(row)

    @staticmethod
    def _row(row) -> WebSession:
        return WebSession(
            id=row["id"], role=row["role"], generation=row["generation"],
            created_at=row["created_at"], last_seen_at=row["last_seen_at"],
            expires_at=row["expires_at"],
            idle_expires_at=min(row["expires_at"], row["last_seen_at"] + IDLE_SECONDS),
            browser_family=row["browser_family"], os_family=row["os_family"],
        )

    def get(self, token: str, *, touch: bool = True) -> SessionLookup:
        if not token:
            return SessionLookup("invalid")
        now = self.clock()
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM web_sessions WHERE token_hash = ?", (_hash_token(token),)
            ).fetchone()
            if row is None:
                return SessionLookup("invalid")
            if row["revoked_at"] is not None or row["generation"] != int(self.generation()):
                return SessionLookup("revoked")
            if row["expires_at"] < now or row["last_seen_at"] + IDLE_SECONDS < now:
                return SessionLookup("expired")
            if touch and now - row["last_seen_at"] >= TOUCH_INTERVAL_SECONDS:
                connection.execute(
                    "UPDATE web_sessions SET last_seen_at = ? WHERE id = ? AND last_seen_at = ?",
                    (now, row["id"], row["last_seen_at"]),
                )
                row = connection.execute(
                    "SELECT * FROM web_sessions WHERE id = ?", (row["id"],)
                ).fetchone()
            return SessionLookup("valid", self._row(row))

    def refresh(self, token: str) -> tuple[SessionLookup, str | None]:
        lookup = self.get(token, touch=False)
        if lookup.status != "valid" or lookup.session is None:
            return lookup, None
        new_token = secrets.token_urlsafe(32)
        now = self.clock()
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE web_sessions SET token_hash = ?, last_seen_at = ? WHERE id = ? AND token_hash = ?",
                (_hash_token(new_token), now, lookup.session.id, _hash_token(token)),
            )
            if cursor.rowcount != 1:
                return SessionLookup("invalid"), None
        return self.get(new_token, touch=False), new_token

    def revoke(self, session_id: str) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE web_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (self.clock(), session_id),
            )
            return cursor.rowcount == 1

    def revoke_all(self) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE web_sessions SET revoked_at = ? WHERE revoked_at IS NULL",
                (self.clock(),),
            )
            return cursor.rowcount

    def is_active_id(self, session_id: str) -> bool:
        now = self.clock()
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT generation, last_seen_at, expires_at, revoked_at "
                "FROM web_sessions WHERE id = ?", (session_id,),
            ).fetchone()
        return bool(
            row is not None
            and row["revoked_at"] is None
            and row["generation"] == int(self.generation())
            and row["expires_at"] >= now
            and row["last_seen_at"] + IDLE_SECONDS >= now
        )

    def list(self) -> list[WebSession]:
        self.cleanup()
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM web_sessions WHERE revoked_at IS NULL ORDER BY created_at DESC"
            ).fetchall()
        return [self._row(row) for row in rows if row["generation"] == int(self.generation())]

    def reset_all(self) -> dict[str, int]:
        """Securely replace the session DB with a fresh empty database.

        The current contents are read only long enough to report deleted row
        counts. The backing DB/WAL files are then best-effort overwritten and
        removed before the schema is recreated. With an active Data Vault the
        replacement database is encrypted before it reaches persistent storage.
        """
        import src.state as state
        vault = get_data_vault(state._CONFIG_DIR)
        encrypted = bool(vault.configured)
        with self._lock:
            connection = sqlite3.connect(":memory:" if encrypted else self.path, timeout=10)
            try:
                if encrypted and self.path.exists():
                    raw = read_bytes(self.path, purpose="web-sessions-db")
                    if raw:
                        connection.deserialize(raw)
                tables = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                ]
                deleted = {}
                for table in tables:
                    quoted = '"' + table.replace('"', '""') + '"'
                    deleted[table] = int(connection.execute(
                        f"SELECT COUNT(*) FROM {quoted}"
                    ).fetchone()[0])
            finally:
                connection.close()
            for path in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
                secure_unlink(path)
            self._initialize()
            return deleted
