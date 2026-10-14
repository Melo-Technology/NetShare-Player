"""High-impact Server controls shared by HTTP routes and the Tkinter runtime."""

import threading
from collections.abc import Callable

import src.state as state
from src.core.file_index import _file_index, _start_watchers, _stop_watcher


class ServerControlService:
    def __init__(self):
        self._lock = threading.RLock()
        self._stop_callback: Callable[[], None] | None = None
        self._stop_requested = False

    def set_stop_callback(self, callback: Callable[[], None] | None) -> None:
        with self._lock:
            self._stop_callback = callback
            if callback is None:
                self._stop_requested = False

    def pause_indexing(self) -> dict:
        changed = _file_index.pause()
        _stop_watcher()
        state._emit("CONTROL  indexing paused by trusted Player", "info")
        return {
            "ok": True,
            "action": "pause_indexing",
            "status": "paused",
            "changed": changed,
            "watcher_running": False,
            "scan_running": False,
        }

    def resume_indexing(self) -> dict:
        changed = _file_index.resume()
        started = _file_index.build_all(state.SHARED_ROOTS)
        _start_watchers(state.SHARED_ROOTS)
        _file_index.start_periodic_flush_all(state.SHARED_ROOTS)
        state._emit("CONTROL  indexing resumed by trusted Player", "info")
        return {
            "ok": True,
            "action": "resume_indexing",
            "status": "running",
            "changed": changed,
            "scan_started": started,
            "watcher_running": True,
        }

    def stop_sharing(self) -> dict | None:
        with self._lock:
            callback = self._stop_callback
            if callback is None:
                return None
            if not self._stop_requested:
                self._stop_requested = True
                callback()
                changed = True
            else:
                changed = False
        state._emit("CONTROL  full sharing stop requested by trusted Player", "info")
        return {
            "ok": True,
            "action": "stop_sharing",
            "status": "stopping",
            "changed": changed,
            "scope": "http_ws_public_tunnel_indexing",
        }


server_control = ServerControlService()
