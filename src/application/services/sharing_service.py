"""Public-sharing application service backed by existing state/session stores."""

from __future__ import annotations

import secrets

from src.core.password_credentials import generate_password
from src.runtime.server_runtime import PUBLIC_HTTP_PORT_OFFSET, server_runtime_controller
from src.runtime.tunnel_runtime import TunnelRuntimeError, tunnel_runtime_controller
from src.runtime.remote_flags_runtime import remote_flags_runtime_controller
from src.runtime.permissions_runtime import permissions_runtime_controller

from ..adapters import StateAdapter, WebSessionAdapter
from ..dto import CloudflareSetupStatusDTO, PublicSharingDTO, TunnelSnapshotDTO, WebSessionDTO
from ..exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationUnavailableError,
    ApplicationValidationError,
)
from .base import BaseApplicationService

_ALLOWED_UPLOAD_MODES = {"direct", "request"}
_MIN_PUBLIC_ADMIN_KEY_LENGTH = 8


class SharingService(BaseApplicationService):
    service_name = "sharing"

    def __init__(
        self,
        state: StateAdapter | None = None,
        sessions: WebSessionAdapter | None = None,
        logger=None,
        *,
        tunnel_runtime=None,
        server_runtime=None,
        remote_flags_runtime=None,
        permissions_runtime=None,
    ):
        self.state = state or StateAdapter()
        self.sessions = sessions or WebSessionAdapter()
        self.tunnel_runtime = tunnel_runtime or tunnel_runtime_controller
        self.server_runtime = server_runtime or server_runtime_controller
        self.remote_flags_runtime = remote_flags_runtime or remote_flags_runtime_controller
        self.permissions_runtime = permissions_runtime or permissions_runtime_controller
        super().__init__(logger)

    def _require_vault_ready(self) -> None:
        s = self.state.state
        config_dir = getattr(s, "_CONFIG_DIR", None)
        if config_dir is None:
            return
        from src.core.data_vault import get_data_vault
        vault = get_data_vault(config_dir)
        if vault.configured and not vault.unlocked:
            retry = getattr(s, "try_auto_unlock_data_vault", None)
            if callable(retry):
                retry()
        if vault.configured and not vault.unlocked:
            raise ApplicationConflictError(
                "data vault must be unlocked to use public sharing",
                code="vault_locked",
            )

    def snapshot(self, *, correlation_id=None) -> PublicSharingDTO:
        return self._execute("snapshot", self._snapshot, correlation_id=correlation_id)

    def _snapshot(self) -> PublicSharingDTO:
        self._require_vault_ready()
        values = self.state.public_values()
        # The Public Sharing configuration must not depend on the encrypted
        # web-session database being immediately readable. The detailed session
        # list has its own DesktopApi endpoint and is loaded independently by the
        # frontend. Keep the legacy count as best-effort compatibility only.
        try:
            values["active_web_sessions"] = len(self.sessions.list())
        except Exception:
            values["active_web_sessions"] = 0
        values["allowed_upload_extensions"] = [str(value) for value in values.get("allowed_upload_extensions", ())]
        values["remote_flags"] = self.remote_flags_runtime.snapshot()
        return PublicSharingDTO(**values)

    def list_web_sessions(self, *, correlation_id=None) -> list[WebSessionDTO]:
        def load():
            self._require_vault_ready()
            return [WebSessionDTO(
                id=item.id, role=item.role, created_at=float(item.created_at),
                last_seen_at=float(item.last_seen_at), expires_at=float(item.expires_at),
                idle_expires_at=float(item.idle_expires_at),
                browser_family=str(item.browser_family), os_family=str(item.os_family),
            ) for item in self.sessions.list()]
        return self._execute("list_web_sessions", load, correlation_id=correlation_id)

    def update_public_config(
        self, *, community_browse_root: bool, community_download: bool,
        community_upload: bool, public_upload_mode: str,
        max_uploads_per_hour: int, max_upload_size_mb: int,
        allowed_upload_extensions, correlation_id=None,
    ) -> PublicSharingDTO:
        mode = str(public_upload_mode or "").strip().lower()
        if mode not in _ALLOWED_UPLOAD_MODES:
            self._validation_error("update_public_config", ApplicationValidationError("invalid upload mode", code="sharing.upload_mode.invalid"), field="public_upload_mode", correlation_id=correlation_id)
        try:
            rate = max(1, int(max_uploads_per_hour))
            size = max(1, int(max_upload_size_mb))
        except (TypeError, ValueError):
            self._validation_error("update_public_config", ApplicationValidationError("invalid upload limits", code="sharing.upload_limits.invalid"), correlation_id=correlation_id)
        extensions = {str(value).lower().strip() for value in allowed_upload_extensions if str(value).strip()}
        def apply():
            self._require_vault_ready()
            self.state.update_public_config(
                COMMUNITY_BROWSE_ROOT=bool(community_browse_root),
                COMMUNITY_DOWNLOAD=bool(community_download),
                COMMUNITY_UPLOAD=bool(community_upload),
                PUBLIC_UPLOAD_MODE=mode,
                MAX_UPLOADS_PER_HOUR=rate,
                MAX_UPLOAD_SIZE_MB=size,
                ALLOWED_UPLOAD_EXTENSIONS=extensions,
            )
            self.log.emit("settings.updated", operation="update_public_config", status="success", settings=["public_sharing"])
            return self._snapshot()
        return self._execute("update_public_config", apply, correlation_id=correlation_id)

    def rotate_access_keys(self, *, correlation_id=None) -> dict[str, str]:
        """Match Tkinter's token_urlsafe(18) key generation and persist hashes."""
        def apply():
            community_key, admin_key = self._new_access_keys()
            return {"community_key": community_key, "admin_key": admin_key}
        return self._execute("rotate_access_keys", apply, correlation_id=correlation_id)

    def _new_access_keys(self) -> tuple[str, str]:
        community_key = secrets.token_urlsafe(18)
        admin_key = secrets.token_urlsafe(18)
        self.state.update_public_config(COMMUNITY_PASSWORD=community_key, ADMIN_PASSWORD=admin_key)
        self.log.emit("settings.updated", operation="rotate_access_keys", status="success", settings=["community_password", "admin_password"], credential_changed=True)
        return community_key, admin_key

    def generate_access_key(self, kind: str, *, correlation_id=None) -> dict[str, str]:
        resolved = str(kind or "").strip().lower()
        if resolved not in {"community", "admin"}:
            self._validation_error("generate_access_key", ApplicationValidationError("invalid access key kind", code="sharing.access_key.kind_invalid"), field="kind", correlation_id=correlation_id)
        def apply():
            value = secrets.token_urlsafe(18)
            if resolved == "community":
                self.state.update_public_config(COMMUNITY_PASSWORD=value)
                field = "community_key"
            else:
                self.state.update_public_config(ADMIN_PASSWORD=value)
                field = "admin_key"
            self.log.emit("settings.updated", operation="generate_access_key", status="success", settings=[f"{resolved}_password"], credential_changed=True)
            return {field: value}
        return self._execute("generate_access_key", apply, correlation_id=correlation_id)

    def set_web_access(self, password: str, *, enabled: bool = True, correlation_id=None) -> PublicSharingDTO:
        if enabled and not str(password or ""):
            self._validation_error("set_web_access", ApplicationValidationError("web password is required", code="sharing.web_password.required"), field="password", correlation_id=correlation_id)
        def apply():
            if enabled:
                self.state.set_web_password(str(password), enabled=True)
            else:
                self.state.disable_web_access()
            self.log.emit("settings.updated", operation="set_web_access", status="success", settings=["web_access"], credential_changed=bool(enabled))
            return self._snapshot()
        return self._execute("set_web_access", apply, correlation_id=correlation_id)

    def generate_web_access_password(self, *, correlation_id=None) -> dict:
        """Mirror Tkinter's generate-web-password workflow and revoke old sessions."""
        def apply():
            password = generate_password()
            self.state.set_web_password(password, enabled=True)
            self.sessions.revoke_all()
            self.log.emit("settings.updated", operation="generate_web_access_password", status="success", settings=["web_access"], credential_changed=True)
            return {"password": password, "sharing": self._snapshot()}
        return self._execute("generate_web_access_password", apply, correlation_id=correlation_id)

    def revoke_web_session(self, session_id: str, *, correlation_id=None) -> bool:
        def apply():
            revoked = self.sessions.revoke(str(session_id))
            if not revoked:
                raise ApplicationNotFoundError("web session not found", code="sharing.web_session.not_found", details={"session_id": str(session_id)[:128]})
            return True
        return self._execute("revoke_web_session", apply, correlation_id=correlation_id)

    def revoke_all_web_sessions(self, *, correlation_id=None) -> int:
        return self._execute("revoke_all_web_sessions", self.sessions.revoke_all, correlation_id=correlation_id)

    # ---- Shared tunnel runtime -------------------------------------------------

    def get_tunnel_status(self, *, correlation_id=None) -> TunnelSnapshotDTO:
        return self._execute("get_tunnel_status", self._tunnel_snapshot, correlation_id=correlation_id)

    def _tunnel_snapshot(self) -> TunnelSnapshotDTO:
        raw = self.tunnel_runtime.snapshot()
        ssh = raw.get("ssh") or {}
        cf = raw.get("cloudflare") or {}
        return TunnelSnapshotDTO(
            ssh={"active": bool(ssh.get("active")), "url": str(ssh.get("url") or "")},
            cloudflare={
                "active": bool(cf.get("active")),
                "url": str(cf.get("url") or ""),
                "hostname": str(cf.get("hostname") or ""),
            },
            any_active=bool(raw.get("any_active")),
        )

    def start_tunnel(self, *, rotate_keys: bool = True, admin_password: str = "", correlation_id=None) -> dict:
        """Start the existing localhost.run tunnel through the shared runtime.

        Tkinter rotates both public keys immediately before public sharing. The
        WebView path defaults to the exact same behavior. Plaintext keys are
        returned once and are never written to structured logs.
        """
        def apply():
            runtime = self.server_runtime.snapshot()
            if not runtime.get("running") or runtime.get("public_port") is None:
                raise ApplicationConflictError("server must be running", code="sharing.server_not_running")
            community_key = ""
            resolved_admin = str(admin_password or "").strip()
            if rotate_keys:
                community_key, resolved_admin = self._new_access_keys()
            elif len(resolved_admin) < _MIN_PUBLIC_ADMIN_KEY_LENGTH:
                raise ApplicationValidationError("admin key is too short", code="sharing.admin_key.too_short", details={"minimum": _MIN_PUBLIC_ADMIN_KEY_LENGTH})
            else:
                self.state.update_public_config(ADMIN_PASSWORD=resolved_admin)
            try:
                self.tunnel_runtime.start_ssh(
                    public_port=int(runtime["public_port"]),
                    admin_password=resolved_admin,
                )
            except TunnelRuntimeError as exc:
                raise ApplicationUnavailableError("public tunnel unavailable", code="sharing.tunnel.unavailable") from exc
            self.log.emit("sharing.updated", operation="start_tunnel", status="success", tunnel="ssh", credential_changed=bool(rotate_keys))
            return {
                "tunnel": self._tunnel_snapshot(),
                "community_key": community_key or None,
                "admin_key": resolved_admin if rotate_keys else None,
            }
        return self._execute("start_tunnel", apply, correlation_id=correlation_id)

    def stop_tunnel(self, *, correlation_id=None) -> TunnelSnapshotDTO:
        def apply():
            self.tunnel_runtime.stop_ssh()
            self.log.emit("sharing.updated", operation="stop_tunnel", status="success", tunnel="ssh")
            return self._tunnel_snapshot()
        return self._execute("stop_tunnel", apply, correlation_id=correlation_id)

    def cloudflare_status(self, hostname: str = "", *, correlation_id=None) -> CloudflareSetupStatusDTO:
        def load():
            raw = self.tunnel_runtime.cloudflare_setup_status(hostname)
            return CloudflareSetupStatusDTO(**raw)
        return self._execute("cloudflare_status", load, correlation_id=correlation_id)

    def cloudflare_login(self, *, correlation_id=None) -> dict:
        return self._execute("cloudflare_login", self.tunnel_runtime.cloudflare_login, correlation_id=correlation_id)

    def cloudflare_setup(self, hostname: str, *, port: int | None = None, correlation_id=None) -> dict:
        hostname = str(hostname or "").strip()
        if not hostname:
            self._validation_error("cloudflare_setup", ApplicationValidationError("hostname required", code="sharing.cloudflare.hostname_required"), field="hostname", correlation_id=correlation_id)
        configured = self.permissions_runtime.snapshot()
        resolved_port = configured.get("port") if port is None else port
        try:
            public_port = int(resolved_port) + PUBLIC_HTTP_PORT_OFFSET
        except (TypeError, ValueError):
            self._validation_error("cloudflare_setup", ApplicationValidationError("invalid port", code="server.port.invalid"), field="port", correlation_id=correlation_id)
        return self._execute("cloudflare_setup", lambda: self.tunnel_runtime.cloudflare_setup(hostname=hostname, public_port=public_port), correlation_id=correlation_id)

    def start_cloudflare_tunnel(self, hostname: str, admin_password: str, *, correlation_id=None) -> TunnelSnapshotDTO:
        hostname = str(hostname or "").strip()
        admin_password = str(admin_password or "").strip()
        if not hostname:
            self._validation_error("start_cloudflare_tunnel", ApplicationValidationError("hostname required", code="sharing.cloudflare.hostname_required"), field="hostname", correlation_id=correlation_id)
        if len(admin_password) < _MIN_PUBLIC_ADMIN_KEY_LENGTH:
            self._validation_error("start_cloudflare_tunnel", ApplicationValidationError("admin key is too short", code="sharing.admin_key.too_short", details={"minimum": _MIN_PUBLIC_ADMIN_KEY_LENGTH}), field="admin_password", correlation_id=correlation_id)
        def apply():
            runtime = self.server_runtime.snapshot()
            if not runtime.get("running") or runtime.get("public_port") is None:
                raise ApplicationConflictError("server must be running", code="sharing.server_not_running")
            # Match Tkinter before process start: update in-memory/persisted admin credential.
            self.state.update_public_config(ADMIN_PASSWORD=admin_password)
            try:
                self.tunnel_runtime.start_cloudflare(
                    hostname=hostname,
                    public_port=int(runtime["public_port"]),
                    admin_password=admin_password,
                )
            except TunnelRuntimeError as exc:
                code = str(exc) if str(exc) in {"cloudflared_not_installed", "cloudflare_setup_incomplete"} else "sharing.cloudflare.unavailable"
                raise ApplicationUnavailableError("Cloudflare tunnel unavailable", code=code) from exc
            self.log.emit("sharing.updated", operation="start_cloudflare_tunnel", status="success", tunnel="cloudflare")
            return self._tunnel_snapshot()
        return self._execute("start_cloudflare_tunnel", apply, correlation_id=correlation_id)

    def stop_cloudflare_tunnel(self, *, correlation_id=None) -> TunnelSnapshotDTO:
        def apply():
            self.tunnel_runtime.stop_cloudflare()
            self.log.emit("sharing.updated", operation="stop_cloudflare_tunnel", status="success", tunnel="cloudflare")
            return self._tunnel_snapshot()
        return self._execute("stop_cloudflare_tunnel", apply, correlation_id=correlation_id)
