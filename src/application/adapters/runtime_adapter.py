"""Read-only probes for mutable runtime singletons.

No new runtime state is invented here.  ``server_running`` remains unknown
until a future shell binds an explicit provider; this avoids inferring a false
state from WebSocket availability.
"""

from __future__ import annotations

from collections.abc import Callable


class RuntimeAdapter:
    def __init__(
        self,
        state_module=None,
        *,
        running_provider: Callable[[], bool] | None = None,
        uptime_provider: Callable[[], float | None] | None = None,
        transfer_speed_provider: Callable[[], float | None] | None = None,
    ):
        if state_module is None:
            import src.state as state_module
        self.state = state_module
        self._running_provider = running_provider
        self._uptime_provider = uptime_provider
        self._transfer_speed_provider = transfer_speed_provider

    def server_running(self) -> bool | None:
        if self._running_provider is None:
            return None
        return bool(self._running_provider())


    def uptime_seconds(self) -> float | None:
        if self._uptime_provider is None:
            return None
        try:
            value = self._uptime_provider()
            return None if value is None else max(0.0, float(value))
        except Exception:
            return None

    def websocket_connections(self) -> int:
        manager = getattr(self.state, "_ws_manager", None)
        counter = getattr(manager, "client_count", None)
        if not callable(counter):
            return 0
        try:
            return max(0, int(counter()))
        except Exception:
            return 0


    def transfer_speed_bps(self) -> float | None:
        try:
            if self._transfer_speed_provider is not None:
                value = self._transfer_speed_provider()
            else:
                from src.runtime.activity_runtime import activity_runtime
                value = activity_runtime.transfer_speed_bps()
            return None if value is None else max(0.0, float(value))
        except Exception:
            return None

    def last_connection_at(self) -> float | None:
        try:
            from src.runtime.connection_runtime import connection_runtime_controller
            value = connection_runtime_controller.last_connection_at()
            return None if value is None else float(value)
        except Exception:
            return None

    def connected_device_ids(self) -> set[str]:
        manager = getattr(self.state, "_ws_manager", None)
        lock = getattr(manager, "_lock", None)
        clients = getattr(manager, "_clients", None)
        if lock is None or not isinstance(clients, dict):
            return set()
        try:
            with lock:
                return {str(device_id) for device_id in clients.values() if device_id}
        except Exception:
            return set()
