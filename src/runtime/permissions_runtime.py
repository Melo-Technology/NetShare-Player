"""Desktop permission/config runtime shared by the PyWebView shell and server.

Keep Alive is a persisted *preference* but the OS wake lock is acquired only
while the HTTP server is actually running.  That avoids holding the machine
awake when NetShare is open but idle and guarantees server stop/app close can
release the process-scoped inhibitor without losing the user's preference.
"""
from __future__ import annotations

import socket
import threading
from typing import Callable, Any

from src.constants import DEFAULT_PORT
from src.utils.sleep import inhibit_sleep, sleep_inhibitor_status


class PermissionsRuntimeController:
    """Authoritative desktop values plus lifecycle-aware Keep Alive control."""

    def __init__(
        self,
        *,
        sleep_setter: Callable[[bool], Any] = inhibit_sleep,
        sleep_status_getter: Callable[[], dict[str, Any]] | None = None,
        initial_keep_awake: bool = False,
        persist_keep_awake: Callable[[bool], Any] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._sleep_setter = sleep_setter
        self._sleep_status_getter = sleep_status_getter
        self._persist_keep_awake = persist_keep_awake
        self._port_text = str(DEFAULT_PORT)
        self._server_name = socket.gethostname()
        self._allow_upload = False
        self._allow_edit = False
        self._keep_awake = bool(initial_keep_awake)
        self._server_running = False
        self._keep_awake_status: dict[str, Any] = {
            "requested": False,
            "active": False,
            "backend": "none",
            "platform": "unknown",
            "error": None,
        }

    def reset_defaults(self) -> None:
        """Reset legacy process-local controls; primarily used by tests/startup."""
        with self._lock:
            self._port_text = str(DEFAULT_PORT)
            self._server_name = socket.gethostname()
            self._allow_upload = False
            self._allow_edit = False
            self._keep_awake = False
            self._server_running = False
        self._apply_sleep_state(force_disable=True)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            raw_port = self._port_text
            try:
                parsed_port = int(raw_port)
            except (TypeError, ValueError):
                parsed_port = None
            status = dict(self._keep_awake_status)
            getter = self._sleep_status_getter
        if getter is not None:
            try:
                fresh = getter()
                if isinstance(fresh, dict):
                    status = dict(fresh)
                    with self._lock:
                        self._keep_awake_status = dict(status)
            except Exception:
                pass
        with self._lock:
            return {
                "port_text": str(raw_port),
                "port": parsed_port,
                "server_name": str(self._server_name),
                "allow_upload": bool(self._allow_upload),
                "allow_edit": bool(self._allow_edit),
                "keep_awake": bool(self._keep_awake),
                "keep_awake_active": bool(status.get("active")),
                "keep_awake_backend": str(status.get("backend") or "none"),
                "keep_awake_error": str(status.get("error")) if status.get("error") else None,
                "server_running": bool(self._server_running),
            }

    def update(
        self,
        *,
        port: object | None = None,
        server_name: object | None = None,
        allow_upload: object | None = None,
        allow_edit: object | None = None,
    ) -> dict[str, object]:
        with self._lock:
            if port is not None:
                self._port_text = str(port)
            if server_name is not None:
                self._server_name = str(server_name)
            if allow_upload is not None:
                self._allow_upload = bool(allow_upload)
            if allow_edit is not None:
                self._allow_edit = bool(allow_edit)
        return self.snapshot()

    def set_keep_awake(self, enabled: bool) -> dict[str, object]:
        desired = bool(enabled)
        with self._lock:
            changed = desired != self._keep_awake
            self._keep_awake = desired
            persist = self._persist_keep_awake
        if changed and persist is not None:
            persist(desired)
        self._apply_sleep_state()
        return self.snapshot()

    def set_server_running(self, running: bool) -> dict[str, object]:
        with self._lock:
            changed = bool(running) != self._server_running
            self._server_running = bool(running)
        if changed:
            self._apply_sleep_state()
        return self.snapshot()

    def release_runtime_inhibitor(self) -> dict[str, object]:
        """Release the OS lock without changing the saved user preference."""
        self._apply_sleep_state(force_disable=True)
        return self.snapshot()

    def toggle_keep_awake(self) -> dict[str, object]:
        with self._lock:
            desired = not self._keep_awake
        return self.set_keep_awake(desired)

    def _apply_sleep_state(self, *, force_disable: bool = False) -> None:
        with self._lock:
            desired = bool(self._keep_awake and self._server_running and not force_disable)
        try:
            result = self._sleep_setter(desired)
            if isinstance(result, dict):
                status = dict(result)
            else:
                status = {
                    "requested": desired,
                    "active": desired,
                    "backend": "injected",
                    "platform": "test",
                    "error": None,
                }
        except Exception as exc:
            status = {
                "requested": desired,
                "active": False,
                "backend": "none",
                "platform": "unknown",
                "error": f"{type(exc).__name__}: {exc}"[:240],
            }
        with self._lock:
            self._keep_awake_status = status


# The singleton imports persisted state only after the state module has finished
# defining its configuration helpers.  This module is not imported by state.
try:
    import src.state as _state
    _initial_keep_awake = bool(getattr(_state, "KEEP_AWAKE_ENABLED", False))
    _persist_keep_awake = getattr(_state, "save_keep_awake_enabled", None)
except Exception:  # pragma: no cover - startup fallback for unusual embedding
    _initial_keep_awake = False
    _persist_keep_awake = None

permissions_runtime_controller = PermissionsRuntimeController(
    initial_keep_awake=_initial_keep_awake,
    persist_keep_awake=_persist_keep_awake,
    sleep_status_getter=sleep_inhibitor_status,
)

__all__ = ["PermissionsRuntimeController", "permissions_runtime_controller"]
