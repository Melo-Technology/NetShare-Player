"""Non-blocking premium-folder discovery shared by desktop frontends.

The source of truth remains ``src.core.unlock_codes.list_premium_folders``.
This runtime only owns a short-lived cache and the background scan lifecycle so UI
snapshots never have to synchronously walk every shared directory.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import src.state as state


class PremiumFoldersRuntime:
    def __init__(self, *, cache_ttl_seconds: float = 30.0):
        self._cache_ttl = max(0.0, float(cache_ttl_seconds))
        self._lock = threading.RLock()
        self._cache_signature: tuple[tuple[str, str], ...] | None = None
        self._cached_folders: list[dict[str, Any]] = []
        self._cached_at = 0.0
        self._scan_signature: tuple[tuple[str, str], ...] | None = None
        self._scan_thread: threading.Thread | None = None
        self._scan_error = ""

    @staticmethod
    def _signature() -> tuple[tuple[str, str], ...]:
        return tuple((str(root.slot), str(root.path)) for root in state.SHARED_ROOTS)

    @staticmethod
    def _parents() -> list[dict[str, str]]:
        return [
            {
                "slot": str(root.slot),
                "path": str(root.path),
                "name": root.path.name or str(root.path),
            }
            for root in state.SHARED_ROOTS
        ]

    def invalidate(self) -> None:
        with self._lock:
            self._cache_signature = None
            self._cached_folders = []
            self._cached_at = 0.0
            # Detach any in-flight scan from the current cache generation.  The
            # worker checks this signature before publishing results, so a scan
            # that started before a destructive SQLite reset cannot repopulate
            # the UI with stale premium-resource rows afterwards.
            self._scan_signature = None
            self._scan_error = ""

    def _cache_fresh_locked(self, signature: tuple[tuple[str, str], ...]) -> bool:
        return (
            self._cache_signature == signature
            and (time.monotonic() - self._cached_at) < self._cache_ttl
        )

    def _scan_running_locked(self, signature: tuple[tuple[str, str], ...]) -> bool:
        return (
            self._scan_signature == signature
            and self._scan_thread is not None
            and self._scan_thread.is_alive()
        )

    def _start_scan_locked(self, signature: tuple[tuple[str, str], ...]) -> None:
        if self._scan_running_locked(signature):
            return
        self._scan_signature = signature
        self._scan_error = ""

        def worker() -> None:
            folders: list[dict[str, Any]] = []
            error = ""
            try:
                from src.core import unlock_codes
                folders = [dict(item) for item in unlock_codes.list_premium_folders()]
            except Exception as exc:  # containment: scan failure must not break Settings
                error = f"{type(exc).__name__}: {exc}"
            finally:
                with self._lock:
                    # Ignore stale work if shared roots changed during the scan.
                    if self._scan_signature == signature:
                        if not error:
                            self._cache_signature = signature
                            self._cached_folders = folders
                            self._cached_at = time.monotonic()
                        self._scan_error = error
                        self._scan_signature = None
                        self._scan_thread = None

        thread = threading.Thread(target=worker, daemon=True, name="premium-folder-scan-shared")
        self._scan_thread = thread
        thread.start()

    def snapshot(self) -> dict[str, Any]:
        signature = self._signature()
        parents = self._parents()
        with self._lock:
            if not self._cache_fresh_locked(signature):
                self._start_scan_locked(signature)
            scanning = self._scan_running_locked(signature)
            folders = list(self._cached_folders) if self._cache_signature == signature else []
            return {
                "parent_folders": parents,
                "folders": [dict(item) for item in folders],
                "scanning": bool(scanning),
                "scan_error": str(self._scan_error or ""),
            }

    def wait_for_scan(self, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() < deadline:
            with self._lock:
                thread = self._scan_thread
            if thread is None:
                return True
            thread.join(timeout=min(0.05, max(0.0, deadline - time.monotonic())))
        with self._lock:
            return self._scan_thread is None


premium_runtime_controller = PremiumFoldersRuntime()
