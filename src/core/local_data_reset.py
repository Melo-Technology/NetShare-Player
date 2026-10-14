"""Administrative reset of regenerable cache and local SQLite data.

The Settings "Clear cache & data" action intentionally has a narrow contract:

* clear generated caches and every row in NetShare's current SQLite stores;
* preserve configuration and credentials (local/public/web passwords, cloud
  tokens, cluster cryptographic identity, security-monitor configuration and
  persisted IP blocks);
* clear local transfer history, live activity/traffic telemetry and security
  event history used by administrative reports;
* refuse the operation while user activity could be disrupted;
* keep an idle HTTP server running and immediately usable after the reset.

This module owns the process-wide maintenance gate used by the HTTP layer to
prevent new requests from racing a reset that has already passed preflight.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
import threading
import time
from typing import Any

import src.state as state
from src.core.data_vault import get_data_vault, secure_unlink


_RESET_LOCK = threading.RLock()
_RESET_ACTIVE = threading.Event()
_JOURNAL_FILENAME = "local_data_reset.journal.json"




def _journal_path() -> Path:
    return Path(state._CONFIG_DIR) / _JOURNAL_FILENAME


def _fsync_parent(path: Path) -> None:
    """Best-effort directory fsync after atomic replace/unlink on POSIX."""
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
    except (AttributeError, OSError):
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _write_reset_journal() -> Path:
    """Durably mark reset intent before the first destructive mutation."""
    path = _journal_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    payload = {
        "version": 1,
        "state": "prepared",
        "started_at": time.time(),
        "pid": os.getpid(),
    }
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    _fsync_parent(path)
    return path


def _remove_reset_journal() -> None:
    path = _journal_path()
    try:
        path.unlink(missing_ok=True)
    finally:
        _fsync_parent(path)


def interrupted_reset_pending() -> bool:
    return _journal_path().is_file()


class LocalDataResetError(RuntimeError):
    """Base class for a safe, user-visible maintenance failure."""


class LocalDataResetBusyError(LocalDataResetError):
    def __init__(self, activity: dict[str, int]):
        self.activity = {str(k): int(v) for k, v in activity.items()}
        super().__init__("active clients or transfers prevent local data reset")


@dataclass(frozen=True)
class ResetStatus:
    server_running: bool
    web_sessions: int
    websocket_clients: int
    web_download_streams: int
    transfer_sessions: int
    pending_uploads: int

    @property
    def busy(self) -> bool:
        return any((
            self.web_sessions,
            self.websocket_clients,
            self.web_download_streams,
            self.transfer_sessions,
            self.pending_uploads,
        ))

    def as_dict(self) -> dict[str, Any]:
        return {
            "server_running": bool(self.server_running),
            "busy": bool(self.busy),
            "activity": {
                "web_sessions": int(self.web_sessions),
                "websocket_clients": int(self.websocket_clients),
                "web_download_streams": int(self.web_download_streams),
                "transfer_sessions": int(self.transfer_sessions),
                "pending_uploads": int(self.pending_uploads),
            },
            "preserved": [
                "local_password",
                "public_access_keys",
                "web_access_password",
                "cloud_session_tokens",
                "cluster_identity_and_keys",
                "security_monitor_configuration",
                "security_ip_blocks",
                "data_vault_configuration",
            ],
            "sqlite_stores": ["web_sessions", "unlock_codes"],
            "deleted_secure_data": ["cloud_reconnect_profiles"],
        }


def maintenance_reset_active() -> bool:
    return _RESET_ACTIVE.is_set()


def _runtime_running() -> bool:
    try:
        from src.runtime.server_runtime import server_runtime_controller
        return bool(server_runtime_controller.is_running())
    except Exception:
        return False


def status() -> ResetStatus:
    try:
        web_sessions = len(state.WEB_SESSION_STORE.list())
    except Exception:
        # If the session DB cannot be inspected, fail closed: a reset must not
        # guess that an inaccessible live session store is idle.
        web_sessions = 1

    ws_clients = 0
    manager = getattr(state, "_ws_manager", None)
    if manager is not None and hasattr(manager, "client_count"):
        try:
            ws_clients = max(0, int(manager.client_count()))
        except Exception:
            ws_clients = 1

    web_streams = 0
    download_store = getattr(state, "WEB_DOWNLOAD_TICKET_STORE", None)
    if download_store is not None and hasattr(download_store, "active_stream_count"):
        try:
            web_streams = max(0, int(download_store.active_stream_count()))
        except Exception:
            web_streams = 1

    try:
        from src.core.transfer_sessions import count_active_transfer_sessions
        transfer_sessions = count_active_transfer_sessions(
            Path(state.INBOX_DIR) / ".netshare-transfers"
        )
    except Exception:
        transfer_sessions = 1

    try:
        with state.UPLOAD_REQUEST_LOCK:
            pending_uploads = len(state.PENDING_UPLOAD_REQUESTS)
    except Exception:
        pending_uploads = 0

    return ResetStatus(
        server_running=_runtime_running(),
        web_sessions=web_sessions,
        websocket_clients=ws_clients,
        web_download_streams=web_streams,
        transfer_sessions=transfer_sessions,
        pending_uploads=pending_uploads,
    )


def _clear_regenerable_caches(*, server_running: bool) -> tuple[dict[str, Any], list[str]]:
    """Clear all known disposable caches, returning stats and soft warnings."""
    results: dict[str, Any] = {}
    warnings: list[str] = []

    # HLS / media caches own locks because deleting an artifact underneath an
    # active generator is unsafe even when the initial activity snapshot was idle.
    from src.core.adaptive_streaming import clear_adaptive_streaming_cache
    results["hls"] = clear_adaptive_streaming_cache()

    from src.core.thumbnail_cache import get_thumbnail_cache
    results["thumbnails"] = get_thumbnail_cache().clear()

    from src.core.waveform import clear_waveform_cache
    results["waveforms"] = clear_waveform_cache()

    from src.core.embedded_tracks import clear_embedded_track_cache
    results["embedded_tracks"] = clear_embedded_track_cache()

    from src.core.cloud import get_manager
    get_manager().invalidate_cache()
    results["cloud_listings"] = {"cleared": True}

    from src.core.cloud.mega import clear_mega_cache
    results["mega"] = clear_mega_cache()

    # Remote Config's disk snapshot is a cache, not configuration authority.
    # Delete only the local JSON file; a future fetch repopulates it.
    try:
        from src.core import firebase
        cache_file = Path(firebase._CACHE_FILE)
        existed = cache_file.exists()
        secure_unlink(cache_file)
        results["remote_config"] = {"files": int(existed)}
    except Exception as exc:
        warnings.append(f"remote_config:{type(exc).__name__}")

    # Process-local derived caches must agree with the freshly cleared stores.
    try:
        from src.utils.network import _cached_id3_metadata
        _cached_id3_metadata.cache_clear()
        results["id3_metadata"] = {"cleared": True}
    except Exception as exc:
        warnings.append(f"id3_metadata:{type(exc).__name__}")
    try:
        import src.deps as deps
        cache = getattr(deps, "_GPU_PROBE_CACHE", None)
        count = len(cache) if isinstance(cache, dict) else 0
        if isinstance(cache, dict):
            cache.clear()
        results["gpu_probe"] = {"entries": count}
    except Exception as exc:
        warnings.append(f"gpu_probe:{type(exc).__name__}")
    try:
        from src.runtime.premium_runtime import premium_runtime_controller
        premium_runtime_controller.invalidate()
        results["premium_snapshot"] = {"cleared": True}
    except Exception as exc:
        warnings.append(f"premium_snapshot:{type(exc).__name__}")

    # The file index cache is regenerable but its in-memory catalogue must be
    # invalidated in the same operation.  If the server is running, immediately
    # start a background rebuild and restore periodic persistence.
    from src.core.file_index import _file_index
    roots = tuple(state.SHARED_ROOTS)
    removed_index_files = 0
    for root in roots:
        cache = _file_index._cache_path(root.path)
        for candidate in (cache, cache.with_suffix(".tmp")):
            try:
                existed = candidate.exists()
                secure_unlink(candidate)
                removed_index_files += int(existed)
            except OSError as exc:
                warnings.append(f"index_cache:{candidate.name}:{type(exc).__name__}")
    _file_index.clear()
    reindex_started = False
    if server_running and roots:
        reindex_started = bool(_file_index.build_all(roots))
        _file_index.start_periodic_flush_all(roots)
    results["file_index"] = {
        "files": removed_index_files,
        "reindex_started": reindex_started,
    }

    return results, warnings


def _reset_sqlite_and_session_memory() -> dict[str, Any]:
    """Reset all SQLite application tables known by this project revision."""
    # Web sessions use short-lived connections guarded by the store lock.
    web_deleted = state.WEB_SESSION_STORE.reset_all()

    # Premium/unlock data uses a persistent connection, and reset_database()
    # explicitly closes/reopens it around the reset transaction.
    from src.core import unlock_codes
    unlock_deleted = unlock_codes.reset_database()

    # These in-memory grants are meaningful only while their corresponding web
    # session exists.  Clear them so memory and the freshly emptied DB agree.
    tickets = getattr(state, "WEB_DOWNLOAD_TICKET_STORE", None)
    ticket_stats = tickets.clear() if tickets is not None and hasattr(tickets, "clear") else {}
    grants = getattr(state, "WEB_MEDIA_GRANT_STORE", None)
    grant_count = grants.clear() if grants is not None and hasattr(grants, "clear") else 0

    return {
        "web_sessions": web_deleted,
        "unlock_codes": unlock_deleted,
        "web_download_tickets": ticket_stats,
        "web_media_grants": int(grant_count),
    }


def _execute_reset(*, server_running: bool) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Idempotent destructive phase used by both normal reset and recovery."""
    cache_results, warnings = _clear_regenerable_caches(server_running=server_running)
    sqlite_results = _reset_sqlite_and_session_memory()
    try:
        from src.core.cloud.profile_store import get_profile_store
        sqlite_results["cloud_reconnect_profiles"] = get_profile_store().clear()
    except Exception as exc:
        warnings.append(f"cloud_reconnect_profiles:{type(exc).__name__}")

    # Administrative report sources are user-clearable local data.  Received
    # files themselves are preserved; only history/telemetry records are reset.
    try:
        from src.core.inbox import InboxService
        sqlite_results["transfer_history"] = InboxService(
            state.INBOX_DIR, state.INBOX_HISTORY_PATH,
        ).purge_history()
    except Exception as exc:
        warnings.append(f"transfer_history:{type(exc).__name__}")
    try:
        from src.runtime.activity_runtime import activity_runtime
        sqlite_results["live_activity"] = activity_runtime.clear()
    except Exception as exc:
        warnings.append(f"live_activity:{type(exc).__name__}")
    try:
        from src.runtime.security_monitor_runtime import security_monitor_runtime
        before = security_monitor_runtime.snapshot(limit=500)
        security_monitor_runtime.clear_history()
        # ``clear_history`` owns the active runtime path. Also clear the journal
        # belonging to the *current* config directory so profile/test rebinding
        # cannot leave stale sensitive history behind. Legacy non-vault installs
        # retain the historical empty-file contract; vault installs keep no
        # plaintext placeholder.
        event_path = Path(state._CONFIG_DIR) / "security_events.jsonl"
        secure_unlink(event_path)
        if not get_data_vault(state._CONFIG_DIR).configured:
            event_path.touch(exist_ok=True)
        sqlite_results["security_event_history"] = len(before.get("events", []))
    except Exception as exc:
        warnings.append(f"security_event_history:{type(exc).__name__}")
    try:
        with state.UPLOAD_REQUEST_LOCK:
            pending_count = len(state.PENDING_UPLOAD_REQUESTS)
            grant_count = len(state.PUBLIC_UPLOAD_GRANTS)
            state.PENDING_UPLOAD_REQUESTS.clear()
            state.PUBLIC_UPLOAD_GRANTS.clear()
        sqlite_results["upload_approval_records"] = {"requests": pending_count, "grants": grant_count}
    except Exception as exc:
        warnings.append(f"upload_approval_records:{type(exc).__name__}")
    return cache_results, sqlite_results, warnings


def recover_interrupted_reset() -> dict[str, Any] | None:
    """Complete a reset that crashed after its durable intent journal was written.

    Recovery is intentionally *completion*, not rollback: cache deletion and
    SQLite DELETEs are idempotent, while reconstructing previously deleted
    cache/database rows is not reliable.  The journal is therefore removed only
    after every reset phase has succeeded.  Until then the HTTP maintenance gate
    remains closed so a partially reset process is never served as healthy.
    """
    with _RESET_LOCK:
        if not interrupted_reset_pending():
            return None
        _RESET_ACTIVE.set()
        success = False
        try:
            cache_results, sqlite_results, warnings = _execute_reset(server_running=False)
            _remove_reset_journal()
            success = True
            try:
                state._emit(
                    "MAINTENANCE completed interrupted local data reset",
                    "warning",
                )
            except Exception:
                pass
            return {
                "recovered": True,
                "cache": cache_results,
                "sqlite": sqlite_results,
                "warnings": warnings,
            }
        finally:
            if success:
                _RESET_ACTIVE.clear()


def clear_cache_and_data() -> dict[str, Any]:
    """Execute the irreversible local-data reset after a strict activity check.

    A durable intent journal is fsync'd before the first destructive step.  If
    the process or machine dies mid-reset, the next desktop/server startup calls
    :func:`recover_interrupted_reset` before accepting traffic and completes the
    same idempotent reset.  That prevents restart into a half-reset state.
    """
    with _RESET_LOCK:
        initial = status()
        if initial.busy:
            raise LocalDataResetBusyError(initial.as_dict()["activity"])

        _RESET_ACTIVE.set()
        success = False
        try:
            # Recheck after closing the HTTP gate so a session/transfer that
            # started between the first status call and the gate cannot race us.
            second = status()
            if second.busy:
                raise LocalDataResetBusyError(second.as_dict()["activity"])

            _write_reset_journal()
            cache_results, sqlite_results, warnings = _execute_reset(
                server_running=second.server_running,
            )
            _remove_reset_journal()
            success = True

            try:
                state._emit(
                    "MAINTENANCE cache and SQLite data cleared from local desktop UI",
                    "warning",
                )
            except Exception:
                pass

            return {
                "cleared": True,
                "server_running": bool(second.server_running),
                "cache": cache_results,
                "sqlite": sqlite_results,
                "warnings": warnings,
                "reindexing": bool(cache_results.get("file_index", {}).get("reindex_started")),
                "preserved": second.as_dict()["preserved"],
                "deleted_secure_data": second.as_dict().get("deleted_secure_data", []),
            }
        finally:
            # If a destructive phase failed after the journal was written, leave
            # the maintenance gate closed.  A retry or restart can safely finish
            # the reset; serving a partially reset state would be less safe.
            if success or not interrupted_reset_pending():
                _RESET_ACTIVE.clear()


__all__ = [
    "LocalDataResetBusyError",
    "LocalDataResetError",
    "ResetStatus",
    "maintenance_reset_active",
    "interrupted_reset_pending",
    "recover_interrupted_reset",
    "status",
    "clear_cache_and_data",
]
