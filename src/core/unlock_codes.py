"""
Premium folders & unlock codes for NetShare Server.

A folder becomes "premium" by dropping a marker file (MARKER_FILENAME) inside
it -- this is the source of truth for "is this folder premium" and travels
naturally with the folder (survives moves/renames handled by the OS, no stale
DB row pointing at a path that no longer exists).

Access codes are stored separately in a local SQLite DB (stdlib, zero extra
dependency). Only the SHA-256 hash of a code is ever persisted; the plaintext
code is returned exactly once, at generation time, and never again.

A code is bound to the first device_id that redeems it. Redeeming the same
code again from a *different* device_id fails with "already_used". Redeeming
again from the *same* device_id is idempotent (returns "ok").

Expiration semantics (confirm with product owner if this should change):
the code grants access until `expires_at` (created_at + ttl_days), whether
or not it has been redeemed yet. Once expired, redemption fails with
"expired" and any previously-granted access also stops being valid.
"""

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

import src.state as state

MARKER_FILENAME = ".netshare_lock.json"
DEFAULT_TTL_DAYS = 30

_DB_PATH = state._CONFIG_DIR / "unlock_codes.db"
_LOCK = threading.RLock()
_conn: sqlite3.Connection | None = None


# DB bootstrap

def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is not None:
        try:
            _conn.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            _conn = None
    if _conn is None:
        state._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS access_codes (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_path  TEXT    NOT NULL,
                code_hash    TEXT    NOT NULL UNIQUE,
                created_at   REAL    NOT NULL,
                expires_at   REAL    NOT NULL,
                device_id    TEXT,
                redeemed_at  REAL,
                revoked      INTEGER NOT NULL DEFAULT 0
            )
        """)
        _conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_codes_folder ON access_codes(folder_path)"
        )
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS premium_resources (
                resource_path TEXT PRIMARY KEY,
                label         TEXT NOT NULL,
                price_note    TEXT NOT NULL DEFAULT '',
                created_at    REAL NOT NULL
            )
        """)
        _conn.commit()
    return _conn


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _normalize_folder(rel_path: str) -> str:
    """Normalize a client-supplied relative path to the '/a/b' form used as key."""
    clean = str(rel_path or "").strip().replace("\\", "/")
    if not clean.startswith("/"):
        clean = "/" + clean
    while "//" in clean:
        clean = clean.replace("//", "/")
    if len(clean) > 1 and clean.endswith("/"):
        clean = clean.rstrip("/")
    return clean or "/"


# Premium marker (folder-side, on disk)

def mark_premium_folder(rel_path: str, label: str, price_note: str = "") -> bool:
    """Drop the marker file inside the target folder. Returns False if the
    folder does not exist under ROOT_DIR or the path escapes ROOT_DIR."""
    from src.utils.network import safe_path
    target = safe_path(rel_path)
    if target is None or not target.is_dir():
        return False
    marker = target / MARKER_FILENAME
    payload = {
        "label": str(label or "").strip() or target.name,
        "price_note": str(price_note or "").strip(),
        "created_at": time.time(),
    }
    try:
        marker.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return True
    except OSError:
        return False


def unmark_premium_folder(rel_path: str) -> bool:
    """Remove the marker file. Existing codes for that folder are left intact
    (in case the host re-marks it later) but stop granting access, since
    is_premium_folder() will report False and callers should short-circuit
    the lock check before it ever reaches redemption logic."""
    from src.utils.network import safe_path
    target = safe_path(rel_path)
    if target is None:
        return False
    marker = target / MARKER_FILENAME
    try:
        marker.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def get_premium_info(rel_path: str) -> dict | None:
    """Return the marker payload for a folder, or None if it isn't premium."""
    db_info = get_premium_resource_info(rel_path)
    if db_info is not None:
        return db_info
    from src.utils.network import safe_path
    target = safe_path(rel_path)
    if target is None or not target.is_dir():
        return None
    marker = target / MARKER_FILENAME
    if not marker.exists():
        return None
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        return {
            "label": data.get("label", target.name),
            "price_note": data.get("price_note", ""),
            "created_at": data.get("created_at", 0),
        }
    except (OSError, json.JSONDecodeError):
        return {"label": target.name, "price_note": "", "created_at": 0}


def is_premium_folder(rel_path: str) -> bool:
    if get_premium_resource_info(rel_path) is not None:
        return True
    from src.utils.network import safe_path
    target = safe_path(rel_path)
    if target is None or not target.is_dir():
        return False
    return (target / MARKER_FILENAME).exists()


def mark_premium_resource(resource_path: str, label: str, price_note: str = "") -> bool:
    """Mark a non-filesystem resource, such as a cloud item, as premium."""
    norm = _normalize_folder(resource_path)
    if norm == "/":
        return False
    now = time.time()
    clean_label = str(label or "").strip() or norm.rsplit("/", 1)[-1]
    clean_note = str(price_note or "").strip()
    with _LOCK:
        conn = _get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO premium_resources "
            "(resource_path, label, price_note, created_at) VALUES (?, ?, ?, ?)",
            (norm, clean_label, clean_note, now),
        )
        conn.commit()
    return True


def unmark_premium_resource(resource_path: str) -> bool:
    norm = _normalize_folder(resource_path)
    with _LOCK:
        conn = _get_conn()
        cur = conn.execute(
            "DELETE FROM premium_resources WHERE resource_path = ?", (norm,)
        )
        conn.commit()
        return cur.rowcount > 0


def get_premium_resource_info(resource_path: str) -> dict | None:
    norm = _normalize_folder(resource_path)
    with _LOCK:
        conn = _get_conn()
        row = conn.execute(
            "SELECT label, price_note, created_at FROM premium_resources "
            "WHERE resource_path = ?",
            (norm,),
        ).fetchone()
    if row is None:
        return None
    label, price_note, created_at = row
    return {"label": label, "price_note": price_note, "created_at": created_at}


def list_premium_folders() -> list[dict]:
    """Walk ROOT_DIR for marker files. Cheap enough since it only touches
    directories, and premium folders are expected to be a small subset."""
    import os
    results = []
    root = state.ROOT_DIR
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if MARKER_FILENAME in filenames:
            folder = Path(dirpath)
            rel = "/" + str(folder.relative_to(root)).replace("\\", "/")
            rel = _normalize_folder(rel if rel != "/." else "/")
            info = get_premium_info(rel) or {}
            results.append({"folder_path": rel, **info})
    with _LOCK:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT resource_path, label, price_note, created_at "
            "FROM premium_resources ORDER BY created_at DESC"
        ).fetchall()
    for path, label, price_note, created_at in rows:
        results.append({
            "folder_path": path,
            "label": label,
            "price_note": price_note,
            "created_at": created_at,
        })
    return results


# Nearest premium ancestor (used to lock sub-content of a premium folder too)

def find_governing_premium_folder(rel_path: str) -> str | None:
    """
    Return the closest premium ancestor folder path that governs access to
    rel_path (which may itself be that folder, or a file/folder inside it),
    or None if nothing in the chain up to root is premium.
    """
    norm = _normalize_folder(rel_path)
    parts = [p for p in norm.split("/") if p]
    # Check from the full path upward to root, most specific first.
    for i in range(len(parts), -1, -1):
        candidate = "/" + "/".join(parts[:i]) if i else "/"
        if candidate == "/":
            # Root itself is never markeable as premium in this design.
            continue
        if is_premium_folder(candidate):
            return _normalize_folder(candidate)
    return None


# Access codes

def generate_code(folder_path: str, ttl_days: float = DEFAULT_TTL_DAYS) -> dict | None:
    """Create a new code for a premium folder. Returns the plaintext code
    (only time it's ever exposed) plus metadata, or None if the folder isn't
    marked premium."""
    norm = _normalize_folder(folder_path)
    if not is_premium_folder(norm):
        return None
    code = secrets.token_urlsafe(16)
    now = time.time()
    expires_at = now + max(ttl_days, 0) * 86400
    with _LOCK:
        conn = _get_conn()
        cur = conn.execute(
            "INSERT INTO access_codes (folder_path, code_hash, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (norm, _hash_code(code), now, expires_at),
        )
        conn.commit()
        code_id = cur.lastrowid
    return {
        "id": code_id,
        "code": code,
        "folder_path": norm,
        "created_at": now,
        "expires_at": expires_at,
    }


def list_codes(folder_path: str | None = None) -> list[dict]:
    """List codes (never includes the plaintext code or its hash)."""
    with _LOCK:
        conn = _get_conn()
        if folder_path:
            rows = conn.execute(
                "SELECT id, folder_path, created_at, expires_at, device_id, "
                "redeemed_at, revoked FROM access_codes WHERE folder_path = ? "
                "ORDER BY created_at DESC",
                (_normalize_folder(folder_path),),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, folder_path, created_at, expires_at, device_id, "
                "redeemed_at, revoked FROM access_codes ORDER BY created_at DESC"
            ).fetchall()
    now = time.time()
    out = []
    for (cid, folder, created_at, expires_at, device_id, redeemed_at, revoked) in rows:
        out.append({
            "id": cid,
            "folder_path": folder,
            "created_at": created_at,
            "expires_at": expires_at,
            "device_id": device_id or None,
            "redeemed_at": redeemed_at,
            "used": bool(device_id),
            "revoked": bool(revoked),
            "expired": expires_at <= now,
        })
    return out


def revoke_code(code_id: int) -> bool:
    device_id = None
    folder_path = None
    with _LOCK:
        conn = _get_conn()
        row = conn.execute(
            "SELECT folder_path, device_id, revoked FROM access_codes WHERE id = ?",
            (code_id,),
        ).fetchone()
        if row is None:
            return False
        folder_path, device_id, revoked = row
        if revoked:
            return False
        cur = conn.execute(
            "UPDATE access_codes SET revoked = 1 WHERE id = ? AND revoked = 0",
            (code_id,),
        )
        conn.commit()
        changed = cur.rowcount > 0
    if changed and device_id and state._ws_manager:
        state._ws_manager.send_to_devices_threadsafe([device_id], {
            "type": "premium_revoked",
            "folder_path": folder_path,
            "folder_name": str(folder_path).rstrip("/").rsplit("/", 1)[-1],
        })
    return changed


def redeem_code(code: str, device_id: str) -> dict:
    """
    Attempt to redeem a code for a device.

    Returns {"status": "ok", "folder_path": ...} on success (first redemption
    or repeat redemption by the same device), or
    {"status": "invalid" | "revoked" | "expired" | "already_used"} otherwise.
    """
    clean_code = str(code or "").strip()
    clean_device = str(device_id or "").strip()
    if not clean_code or not clean_device:
        return {"status": "invalid"}

    code_hash = _hash_code(clean_code)
    now = time.time()
    first_redemption = False
    with _LOCK:
        conn = _get_conn()
        row = conn.execute(
            "SELECT id, folder_path, expires_at, device_id, revoked "
            "FROM access_codes WHERE code_hash = ?",
            (code_hash,),
        ).fetchone()
        if row is None:
            return {"status": "invalid"}
        code_id, folder_path, expires_at, existing_device, revoked = row
        if revoked:
            return {"status": "revoked"}
        if expires_at <= now:
            return {"status": "expired"}
        if existing_device:
            if existing_device == clean_device:
                return {"status": "ok", "folder_path": folder_path}
            return {"status": "already_used"}
        conn.execute(
            "UPDATE access_codes SET device_id = ?, redeemed_at = ? WHERE id = ?",
            (clean_device, now, code_id),
        )
        conn.commit()
        first_redemption = True
    if first_redemption and state._ws_manager:
        state._ws_manager.send_to_devices_threadsafe([clean_device], {
            "type": "premium_redeemed",
            "folder_path": folder_path,
            "folder_name": str(folder_path).rstrip("/").rsplit("/", 1)[-1],
        })
    return {"status": "ok", "folder_path": folder_path}


def is_unlocked_for_device(folder_path: str, device_id: str) -> bool:
    """True if this device holds a valid (non-revoked, non-expired) redeemed
    code for this exact premium folder."""
    clean_device = str(device_id or "").strip()
    if not clean_device:
        return False
    norm = _normalize_folder(folder_path)
    now = time.time()
    with _LOCK:
        conn = _get_conn()
        row = conn.execute(
            "SELECT 1 FROM access_codes WHERE folder_path = ? AND device_id = ? "
            "AND revoked = 0 AND expires_at > ? LIMIT 1",
            (norm, clean_device, now),
        ).fetchone()
    return row is not None


def migrate_device_id(previous_device_id: str, device_id: str) -> int:
    """Move existing premium grants from a legacy install ID to a scoped ID.

    Both identifiers are bearer identifiers rather than secrets. This migration
    preserves existing grants while clients move to per-server pseudonyms.
    """
    previous = str(previous_device_id or "").strip()
    current = str(device_id or "").strip()
    if not previous or not current or previous == current:
        return 0
    with _LOCK:
        conn = _get_conn()
        cur = conn.execute(
            "UPDATE access_codes SET device_id = ? WHERE device_id = ?",
            (current, previous),
        )
        conn.commit()
        return cur.rowcount


def lock_status_for_path(rel_path: str, device_id: str) -> dict:
    """
    Single entry point handler.py should call for any path (file or folder)
    being listed, searched, or downloaded.

    Returns {"locked": False} when nothing premium governs this path, or
    {"locked": True, "folder_path": ..., "label": ..., "price_note": ...}
    when it sits under a premium folder the device hasn't unlocked.
    """
    governing = find_governing_premium_folder(rel_path)
    if governing is None:
        return {"locked": False}
    if is_unlocked_for_device(governing, device_id):
        return {"locked": False}
    info = get_premium_info(governing) or {}
    return {
        "locked": True,
        "folder_path": governing,
        "label": info.get("label", ""),
        "price_note": info.get("price_note", ""),
    }
