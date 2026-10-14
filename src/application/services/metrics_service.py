"""Single source for dashboard metrics available from the current core."""

from __future__ import annotations

from ..adapters import FileIndexAdapter, NetworkAdapter, RuntimeAdapter, StateAdapter, WebSessionAdapter
from ..dto import MetricsSnapshotDTO
from .base import BaseApplicationService


class MetricsService(BaseApplicationService):
    service_name = "metrics"

    def __init__(self, state=None, file_index=None, network=None, runtime=None, sessions=None, logger=None):
        self.state = state or StateAdapter()
        self.file_index = file_index or FileIndexAdapter()
        self.network = network or NetworkAdapter()
        self.runtime = runtime or RuntimeAdapter(self.state.state)
        self.sessions = sessions or WebSessionAdapter()
        super().__init__(logger)

    def snapshot(self, *, correlation_id=None) -> MetricsSnapshotDTO:
        def collect():
            pending = sum(1 for item in self.state.pending_uploads() if str(item.get("status")) == "pending")
            uptime = self.runtime.uptime_seconds()
            web_sessions = tuple(self.sessions.list())
            active_web_sessions = len(web_sessions)
            websocket_clients = self.runtime.websocket_connections()
            session_last_seen = max(
                (float(getattr(session, "last_seen_at", 0.0) or 0.0) for session in web_sessions),
                default=0.0,
            ) or None
            runtime_last_connection = self.runtime.last_connection_at()
            transfer_speed_provider = getattr(self.runtime, "transfer_speed_bps", None)
            transfer_speed = transfer_speed_provider() if callable(transfer_speed_provider) else None
            last_connection = max(
                (value for value in (runtime_last_connection, session_last_seen) if value is not None),
                default=None,
            )
            unavailable = [
                name for name, value in (
                    ("uptime_seconds", uptime),
                    ("transfer_speed_bps", transfer_speed),
                    ("bandwidth_week_bytes", None),
                    ("last_connection_at", last_connection),
                ) if value is None
            ]
            result = MetricsSnapshotDTO(
                indexed_files=self.file_index.total_files(),
                index_ready=self.file_index.ready(),
                # Browser sessions are active clients too, even though they do not
                # hold the local WebSocket used by paired Player devices.
                connected_clients=websocket_clients + active_web_sessions,
                shared_folder_count=len(self.state.shared_roots()),
                pending_uploads=pending,
                active_web_sessions=active_web_sessions,
                network_addresses=list(self.network.local_ips()),
                uptime_seconds=uptime,
                transfer_speed_bps=transfer_speed,
                bandwidth_week_bytes=None,
                last_connection_at=last_connection,
                unavailable=unavailable,
            )
            self.log.emit("metrics.collected", operation="snapshot", status="success", available_count=10-len(unavailable), unavailable=list(unavailable))
            return result
        return self._execute("snapshot", collect, correlation_id=correlation_id)
