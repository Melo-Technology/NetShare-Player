"""Server lifecycle and read-only projection for desktop frontends."""

from __future__ import annotations

from pathlib import Path
import socket
from urllib.parse import urlparse

from src.constants import DEFAULT_PORT, VERSION
from src.runtime.server_runtime import ServerRuntimeController, server_runtime_controller
from src.runtime.remote_flags_runtime import remote_flags_runtime_controller
from src.runtime.permissions_runtime import permissions_runtime_controller
from src.runtime.connection_runtime import connection_runtime_controller

from ..adapters import NetworkAdapter, RuntimeAdapter, StateAdapter
from ..dto import ServerSnapshotDTO, SharedRootDTO
from ..exceptions import ApplicationConflictError, ApplicationValidationError
from .base import BaseApplicationService


class ServerService(BaseApplicationService):
    service_name = "server"

    def __init__(
        self,
        state=None,
        network=None,
        runtime=None,
        logger=None,
        runtime_controller: ServerRuntimeController | None = None,
        permissions_runtime=None,
        remote_flags_runtime=None,
    ):
        self.state = state or StateAdapter()
        self.network = network or NetworkAdapter()
        self.controller = runtime_controller or server_runtime_controller
        self.permissions_runtime = permissions_runtime or permissions_runtime_controller
        self.remote_flags_runtime = remote_flags_runtime or remote_flags_runtime_controller
        self.runtime = runtime or RuntimeAdapter(
            self.state.state, running_provider=self.controller.is_running
        )
        super().__init__(logger)

    def _snapshot(self) -> ServerSnapshotDTO:
        roots = [
            SharedRootDTO(
                slot=str(root.slot),
                path=str(root.path),
                name=Path(root.path).name or str(root.path),
            )
            for root in self.state.shared_roots()
        ]
        s = self.state.state
        runtime = self.controller.snapshot()
        configured = self.permissions_runtime.snapshot()
        running = bool(runtime.get("running"))
        return ServerSnapshotDTO(
            version=VERSION,
            server_name=str(s.SERVER_NAME if running else configured.get("server_name") or s.SERVER_NAME),
            port=runtime.get("port") if running else configured.get("port"),
            websocket_port=runtime.get("websocket_port"),
            public_port=runtime.get("public_port"),
            started_at=runtime.get("started_at"),
            uptime_seconds=runtime.get("uptime_seconds"),
            shared_roots=roots,
            feature_flags={
                str(key): bool(value) for key, value in self.state.feature_flags().items()
            },
            cluster_role=str(s.CLUSTER_ROLE),
            server_running=running,
            websocket_connections=self.runtime.websocket_connections(),
            network_addresses=list(self.network.local_ips()) if running else [],
        )

    def snapshot(self, *, correlation_id=None) -> ServerSnapshotDTO:
        return self._execute("snapshot", self._snapshot, correlation_id=correlation_id)

    def connection_qr(self, address: str, *, correlation_id=None) -> dict:
        def load():
            snapshot = self._snapshot()
            if not snapshot.get("server_running"):
                raise ApplicationConflictError("server is not running", code="server.not_running")
            clean = str(address or "").strip()
            allowed = {
                f"http://{host}:{snapshot.get('port')}"
                for host in snapshot.get("network_addresses", [])
                if snapshot.get("port")
            }
            if clean not in allowed:
                raise ApplicationValidationError("invalid connection address", code="server.connection_address.invalid")
            data_url = connection_runtime_controller.qr_data_url(clean)
            return {"available": bool(data_url), "data_url": data_url, "address": clean}
        return self._execute("connection_qr", load, correlation_id=correlation_id)

    def qr_code(self, value: str, *, correlation_id=None) -> dict:
        """Generate a QR for an explicit HTTP(S) URL used by local desktop UI.

        Unlike ``connection_qr`` this is not a LAN-connectivity assertion; it
        is intended for public tunnel/Web URLs and therefore validates only the
        URL shape and excludes embedded credentials.
        """
        def load():
            clean = str(value or "").strip()
            if not clean or len(clean) > 2048:
                raise ApplicationValidationError("invalid QR value", code="server.qr.invalid")
            try:
                parsed = urlparse(clean)
                _ = parsed.port
            except ValueError:
                raise ApplicationValidationError("invalid QR URL", code="server.qr.invalid")
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise ApplicationValidationError("invalid QR URL", code="server.qr.invalid")
            data_url = connection_runtime_controller.qr_data_url(clean)
            return {"available": bool(data_url), "data_url": data_url, "value": clean}
        return self._execute("qr_code", load, correlation_id=correlation_id)

    def start(
        self,
        *,
        port: int | None = None,
        server_name: str | None = None,
        allow_upload: bool | None = None,
        allow_edit: bool | None = None,
        acknowledge_password_reminder: bool = False,
        allow_no_password: bool = False,
        correlation_id=None,
    ) -> ServerSnapshotDTO:
        s = self.state.state
        config_dir = getattr(s, "_CONFIG_DIR", None)
        if config_dir is not None:
            from src.core.data_vault import get_data_vault
            from src.core.data_vault_migration import MIGRATION_VERSION, migration_snapshot
            vault = get_data_vault(config_dir)
            if vault.configured and not vault.unlocked:
                retry = getattr(s, "try_auto_unlock_data_vault", None)
                if callable(retry):
                    retry()
            if vault.configured and not vault.unlocked:
                raise ApplicationConflictError(
                    "data vault must be unlocked before the server can start",
                    code="server.vault_locked",
                )
            if vault.configured and vault.migration_version < MIGRATION_VERSION:
                progress = migration_snapshot()
                raise ApplicationConflictError(
                    "data vault migration must complete before the server can start",
                    code="server.vault_migration_incomplete",
                    details={"migration": progress},
                )
            if getattr(s, "data_vault_boot_error", lambda: "")():
                raise ApplicationConflictError(
                    "data vault protected state could not be loaded",
                    code="server.vault_state_unavailable",
                )
        configured = self.permissions_runtime.snapshot()
        resolved_port_value = configured.get("port") if port is None else port
        resolved_server_name = configured.get("server_name") if server_name is None else server_name
        resolved_allow_upload = configured.get("allow_upload") if allow_upload is None else allow_upload
        resolved_allow_edit = configured.get("allow_edit") if allow_edit is None else allow_edit
        try:
            resolved_port = int(resolved_port_value)
        except (TypeError, ValueError):
            self._validation_error(
                "start",
                ApplicationValidationError(
                    "invalid server port", code="server.port.invalid"
                ),
                field="port",
                correlation_id=correlation_id,
            )
            raise AssertionError("unreachable")
        if not 1 <= resolved_port <= 65532:
            self._validation_error(
                "start",
                ApplicationValidationError(
                    "invalid server port", code="server.port.invalid"
                ),
                field="port",
                correlation_id=correlation_id,
            )
        roots = self.state.shared_roots()
        if not roots:
            self._validation_error(
                "start",
                ApplicationValidationError(
                    "shared root required", code="server.shared_root.required"
                ),
                field="shared_roots",
                correlation_id=correlation_id,
            )
        for root in roots:
            path = Path(root.path)
            if not path.exists() or not path.is_dir():
                self._validation_error(
                    "start",
                    ApplicationValidationError(
                        "shared root is invalid",
                        code="server.shared_root.invalid",
                        details={"path": str(path)},
                    ),
                    field="shared_roots",
                    correlation_id=correlation_id,
                )

        requested_password = str(s.SAVED_LOCAL_PASSWORD or "").strip()
        if requested_password and s.password_reminder_due():
            if not acknowledge_password_reminder:
                raise ApplicationConflictError(
                    "password reminder requires confirmation",
                    code="server.password_reminder_due",
                    details={"days": int(s.PASSWORD_REMINDER_DAYS)},
                    correlation_id=correlation_id,
                )
            s.postpone_password_reminder()
        if not requested_password and not allow_no_password:
            raise ApplicationConflictError(
                "starting without password requires confirmation",
                code="server.no_password_confirmation_required",
                correlation_id=correlation_id,
            )

        def apply():
            self.controller.start(
                shared_roots=[str(root.path) for root in roots],
                port=resolved_port,
                server_name=str(resolved_server_name or s.SERVER_NAME or socket.gethostname()),
                local_password=requested_password,
                allow_upload=bool(resolved_allow_upload),
                allow_edit=bool(resolved_allow_edit),
                community_password=str(s.COMMUNITY_PASSWORD or ""),
                admin_password=str(s.ADMIN_PASSWORD or ""),
                community_browse_root=bool(s.COMMUNITY_BROWSE_ROOT),
                community_download=bool(s.COMMUNITY_DOWNLOAD),
                community_upload=bool(s.COMMUNITY_UPLOAD),
                public_upload_mode=str(s.PUBLIC_UPLOAD_MODE),
                max_uploads_per_hour=int(s.MAX_UPLOADS_PER_HOUR),
                max_upload_size_mb=int(s.MAX_UPLOAD_SIZE_MB),
                allowed_upload_extensions=set(s.ALLOWED_UPLOAD_EXTENSIONS),
                remote_flags=self.remote_flags_runtime.snapshot(),
            )
            self.log.emit(
                "server.status.changed",
                operation="start",
                status="success",
                running=True,
            )
            return self._snapshot()

        return self._execute("start", apply, correlation_id=correlation_id)

    def stop(self, *, correlation_id=None) -> ServerSnapshotDTO:
        def apply():
            self.controller.stop()
            self.log.emit(
                "server.status.changed",
                operation="stop",
                status="success",
                running=False,
            )
            return self._snapshot()

        return self._execute("stop", apply, correlation_id=correlation_id)
