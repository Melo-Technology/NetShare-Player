"""Application-service composition root (no DesktopApi / no WebView)."""

from __future__ import annotations

from dataclasses import dataclass

from ..adapters import FileIndexAdapter, NetworkAdapter, RuntimeAdapter, StateAdapter, WebSessionAdapter
from ..observability import CompositeLogSink, PythonLoggingSink, StateLogSink, StructuredLogger
from .activity_service import ActivityService
from .device_service import DeviceService
from .metrics_service import MetricsService
from .server_service import ServerService
from .settings_service import SettingsService
from .sharing_service import SharingService


@dataclass(slots=True)
class ApplicationServices:
    server: ServerService
    settings: SettingsService
    sharing: SharingService
    devices: DeviceService
    activity: ActivityService
    metrics: MetricsService


def build_application_services(*, running_provider=None, log_sink=None, runtime_controller=None, tunnel_runtime=None) -> ApplicationServices:
    """Wire services around the current core without mutating its schemas."""
    from src.runtime.server_runtime import server_runtime_controller
    from src.runtime.tunnel_runtime import tunnel_runtime_controller
    from src.runtime.pairing_runtime import pairing_runtime_controller
    from src.runtime.activity_runtime import activity_runtime

    controller = runtime_controller or server_runtime_controller
    tunnel_controller = tunnel_runtime or tunnel_runtime_controller
    state = StateAdapter()
    sessions = WebSessionAdapter()
    network = NetworkAdapter()
    file_index = FileIndexAdapter()
    runtime = RuntimeAdapter(
        state.state,
        running_provider=running_provider or controller.is_running,
        uptime_provider=controller.uptime_seconds,
    )
    sink = log_sink or CompositeLogSink((PythonLoggingSink(), StateLogSink()))

    def logger(name):
        return StructuredLogger(name, sink)

    return ApplicationServices(
        server=ServerService(state, network, runtime, logger("ServerService"), runtime_controller=controller),
        settings=SettingsService(state, logger("SettingsService"), runtime_controller=controller),
        sharing=SharingService(
            state, sessions, logger("SharingService"),
            tunnel_runtime=tunnel_controller, server_runtime=controller,
        ),
        devices=DeviceService(state, runtime, logger("DeviceService"), pairing_runtime=pairing_runtime_controller),
        activity=ActivityService(state, logger("ActivityService"), activity_runtime=activity_runtime),
        metrics=MetricsService(state, file_index, network, runtime, sessions, logger("MetricsService")),
    )


__all__ = [
    "ActivityService", "ApplicationServices", "DeviceService", "MetricsService",
    "ServerService", "SettingsService", "SharingService", "build_application_services",
]
