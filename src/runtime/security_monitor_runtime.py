"""Runtime singleton and persistence bridge for Security Monitoring."""
from __future__ import annotations

from typing import Any

import src.state as state
from src.core.security_monitor import SecurityMonitor
from src.utils.notifications import notify_system


class SecurityMonitorRuntime:
    def __init__(self) -> None:
        self._monitor = SecurityMonitor(
            config_dir=state._CONFIG_DIR,
            config=state.SECURITY_MONITOR_CONFIG,
            notifier=notify_system,
        )

    def snapshot(self, *, limit: int = 200) -> dict[str, Any]:
        return self._monitor.snapshot(limit=limit)

    def configure(self, values: dict[str, Any]) -> dict[str, Any]:
        saved = state.save_security_monitor_config(values)
        return self._monitor.configure(saved)

    def clear_history(self) -> dict[str, Any]:
        self._monitor.clear_history()
        return self.snapshot()

    def unblock(self, ip: str) -> dict[str, Any]:
        self._monitor.unblock(ip)
        return self.snapshot()

    def inspect_request(self, *, ip: str, method: str, path: str):
        return self._monitor.inspect_request(ip=ip, method=method, path=path)

    def record_auth_failure(self, *, ip: str, kind: str, path: str = "") -> dict[str, Any]:
        return self._monitor.record_auth_failure(ip=ip, kind=kind, path=path)

    def record_auth_success(self, *, ip: str) -> None:
        self._monitor.record_auth_success(ip=ip)

    def record_not_found(self, *, ip: str, method: str, path: str) -> dict[str, Any]:
        return self._monitor.record_not_found(ip=ip, method=method, path=path)


security_monitor_runtime = SecurityMonitorRuntime()

__all__ = ["SecurityMonitorRuntime", "security_monitor_runtime"]
