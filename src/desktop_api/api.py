"""Desktop-facing API boundary over the frozen Application Services layer.

This module has no dependency on PyWebView and no knowledge of Tkinter, HTTP
routes, ``src.state`` or ``src.core``.  It exists solely to present a stable,
JSON-safe call surface to a future desktop frontend.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, TypeVar

from src.application.correlation import correlation_scope
from src.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationOperationError,
    ApplicationServiceError,
    ApplicationUnavailableError,
    ApplicationValidationError,
)
from src.application.observability import StructuredLogger
from src.secret_redaction import is_sensitive_secret_name, redact_secret_text
from src.application.services import ApplicationServices, build_application_services

from .contracts import ApiError, ApiResponse

_T = TypeVar("_T")


class DesktopApi:
    """JSON-only façade over :class:`ApplicationServices`.

    Every public method returns the same response envelope::

        {
            "ok": True | False,
            "data": <JSON-native value or None>,
            "error": <error object or None>,
            "meta": {"correlation_id": "..."},
        }

    Application-service exceptions are contained at this boundary so a future
    UI failure cannot propagate into the server/runtime.  Unexpected exceptions
    are also contained and translated into a generic ``desktop_api.internal``
    response while their technical type is retained only in structured logs.
    """

    def __init__(
        self,
        services: ApplicationServices | None = None,
        *,
        logger: StructuredLogger | None = None,
    ):
        self._services = services or build_application_services()
        self._log = logger or StructuredLogger("DesktopApi")
        self._emit_log(
            "desktop_api.initialized",
            operation="initialize",
            status="success",
        )

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------
    def get_server_snapshot(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_server_snapshot",
            lambda cid: self._services.server.snapshot(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def start_server(
        self,
        port: int | None = None,
        server_name: str | None = None,
        allow_upload: bool | None = None,
        allow_edit: bool | None = None,
        acknowledge_password_reminder: bool = False,
        allow_no_password: bool = False,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "start_server",
            lambda cid: self._services.server.start(
                port=port,
                server_name=server_name,
                allow_upload=allow_upload,
                allow_edit=allow_edit,
                acknowledge_password_reminder=bool(acknowledge_password_reminder),
                allow_no_password=bool(allow_no_password),
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def stop_server(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "stop_server",
            lambda cid: self._services.server.stop(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def get_connection_qr(self, address: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_connection_qr",
            lambda cid: self._services.server.connection_qr(address, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def get_qr_code(self, value: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_qr_code",
            lambda cid: self._services.server.qr_code(value, correlation_id=cid),
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------
    def get_settings_snapshot(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_settings_snapshot",
            lambda cid: self._services.settings.snapshot(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_appearance(
        self,
        theme: str | None = None,
        text_size: str | None = None,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "update_appearance",
            lambda cid: self._services.settings.update_appearance(
                theme=theme,
                text_size=text_size,
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def update_language(self, language: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "update_language",
            lambda cid: self._services.settings.update_language(language, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_advanced_visibility(self, enabled: bool, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "update_advanced_visibility",
            lambda cid: self._services.settings.update_advanced_visibility(bool(enabled), correlation_id=cid),
            correlation_id=correlation_id,
        )

    def get_local_password_secret(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_local_password_secret",
            lambda cid: self._services.settings.get_local_password_secret(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_local_password(
        self,
        password: str,
        reminder_days: int | None = None,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "update_local_password",
            lambda cid: self._services.settings.update_local_password(
                password,
                reminder_days=reminder_days,
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def update_password_reminder(self, reminder_days: int, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "update_password_reminder",
            lambda cid: self._services.settings.update_password_reminder(reminder_days, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_ffmpeg_path(self, path: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "update_ffmpeg_path",
            lambda cid: self._services.settings.update_ffmpeg_path(path, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_performance_preset(self, preset: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "update_performance_preset",
            lambda cid: self._services.settings.update_performance_preset(preset, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_worker_budget(
        self,
        index_workers: object,
        analysis_workers: object,
        changed: str,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "update_worker_budget",
            lambda cid: self._services.settings.update_worker_budget(
                index_workers,
                analysis_workers,
                changed=changed,
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def update_gpu_preference(
        self,
        preference: str,
        capabilities: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "update_gpu_preference",
            lambda cid: self._services.settings.update_gpu_preference(
                preference,
                capabilities=dict(capabilities) if capabilities is not None else None,
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def update_log_buffer_lines(self, value: object, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "update_log_buffer_lines",
            lambda cid: self._services.settings.update_log_buffer_lines(value, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_cluster_role(self, role: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "update_cluster_role",
            lambda cid: self._services.settings.update_cluster_role(role, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_hidden_path(
        self,
        slot: str,
        relative_path: str,
        hidden: bool,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "update_hidden_path",
            lambda cid: self._services.settings.update_hidden_path(
                slot,
                relative_path,
                bool(hidden),
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def set_shared_roots(
        self,
        paths: Sequence[str],
        persist: bool = True,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "set_shared_roots",
            lambda cid: self._services.settings.set_shared_roots(
                list(paths),
                persist=bool(persist),
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def clear_folder_history(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "clear_folder_history",
            lambda cid: self._services.settings.clear_folder_history(correlation_id=cid),
            correlation_id=correlation_id,
        )


    # ------------------------------------------------------------------
    # Extended Settings capabilities
    # ------------------------------------------------------------------
    def get_permissions_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_permissions_settings", lambda cid: self._services.settings.get_permissions(correlation_id=cid), correlation_id=correlation_id)

    def update_permissions_settings(self, port=None, server_name=None, allow_upload=None, allow_edit=None, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("update_permissions_settings", lambda cid: self._services.settings.update_permissions(port=port, server_name=server_name, allow_upload=allow_upload, allow_edit=allow_edit, correlation_id=cid), correlation_id=correlation_id)

    def set_transport_tls(self, enabled: bool, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "set_transport_tls",
            lambda cid: self._services.settings.set_transport_tls(bool(enabled), correlation_id=cid),
            correlation_id=correlation_id,
        )

    def set_keep_awake(self, enabled: bool, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("set_keep_awake", lambda cid: self._services.settings.set_keep_awake(bool(enabled), correlation_id=cid), correlation_id=correlation_id)

    def rescan_media(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("rescan_media", lambda cid: self._services.settings.rescan_media(correlation_id=cid), correlation_id=correlation_id)

    def get_performance_details(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_performance_details", lambda cid: self._services.settings.get_performance_details(correlation_id=cid), correlation_id=correlation_id)

    def get_ffmpeg_details(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_ffmpeg_details", lambda cid: self._services.settings.get_ffmpeg_details(correlation_id=cid), correlation_id=correlation_id)

    def recheck_ffmpeg(self, path: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("recheck_ffmpeg", lambda cid: self._services.settings.recheck_ffmpeg(path, correlation_id=cid), correlation_id=correlation_id)

    def get_ffmpeg_install_plan(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_ffmpeg_install_plan", lambda cid: self._services.settings.get_ffmpeg_install_plan(correlation_id=cid), correlation_id=correlation_id)

    def install_ffmpeg(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("install_ffmpeg", lambda cid: self._services.settings.install_ffmpeg(correlation_id=cid), correlation_id=correlation_id)

    def get_premium_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_premium_settings", lambda cid: self._services.settings.get_premium(correlation_id=cid), correlation_id=correlation_id)

    def mark_premium_folder(self, path: str, label: str, price_note: str = "", correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("mark_premium_folder", lambda cid: self._services.settings.mark_premium_folder(path, label, price_note, correlation_id=cid), correlation_id=correlation_id)

    def generate_premium_code(self, folder_path: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("generate_premium_code", lambda cid: self._services.settings.generate_premium_code(folder_path, correlation_id=cid), correlation_id=correlation_id)

    def revoke_premium_code(self, code_id: int, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("revoke_premium_code", lambda cid: self._services.settings.revoke_premium_code(code_id, correlation_id=cid), correlation_id=correlation_id)

    def get_cloud_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_cloud_settings", lambda cid: self._services.settings.get_cloud(correlation_id=cid), correlation_id=correlation_id)

    def connect_cloud(self, provider: str, client_id: str = "", client_secret: str = "", app_key: str = "", email: str = "", password: str = "", correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("connect_cloud", lambda cid: self._services.settings.connect_cloud(provider, client_id=client_id, client_secret=client_secret, app_key=app_key, email=email, password=password, correlation_id=cid), correlation_id=correlation_id)

    def reconnect_cloud(self, profile_id: str, password: str = "", correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("reconnect_cloud", lambda cid: self._services.settings.reconnect_cloud(profile_id, password=password, correlation_id=cid), correlation_id=correlation_id)

    def forget_cloud_profile(self, profile_id: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("forget_cloud_profile", lambda cid: self._services.settings.forget_cloud_profile(profile_id, correlation_id=cid), correlation_id=correlation_id)

    def disconnect_cloud(self, provider_id: str, account_id: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("disconnect_cloud", lambda cid: self._services.settings.disconnect_cloud(provider_id, account_id, correlation_id=cid), correlation_id=correlation_id)

    def get_inbox_management(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_inbox_management", lambda cid: self._services.settings.get_inbox_management(correlation_id=cid), correlation_id=correlation_id)

    def open_inbox_folder(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("open_inbox_folder", lambda cid: self._services.settings.open_inbox_folder(correlation_id=cid), correlation_id=correlation_id)

    def export_transfer_report(self, target_path: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("export_transfer_report", lambda cid: self._services.settings.export_transfer_report(target_path, correlation_id=cid), correlation_id=correlation_id)

    def export_server_report(self, target_path: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("export_server_report", lambda cid: self._services.settings.export_server_report(target_path, correlation_id=cid), correlation_id=correlation_id)

    def get_folder_tree(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_folder_tree", lambda cid: self._services.settings.get_folder_tree(correlation_id=cid), correlation_id=correlation_id)

    def get_folder_children(self, path: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_folder_children", lambda cid: self._services.settings.get_folder_children(path, correlation_id=cid), correlation_id=correlation_id)

    def set_folder_visibility(self, path: str, hidden: bool, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("set_folder_visibility", lambda cid: self._services.settings.set_folder_visibility(path, bool(hidden), correlation_id=cid), correlation_id=correlation_id)

    def get_guest_profiles(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_guest_profiles", lambda cid: self._services.settings.get_guest_profiles(correlation_id=cid), correlation_id=correlation_id)

    def create_guest_profile(self, name: str, folder_path: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("create_guest_profile", lambda cid: self._services.settings.create_guest_profile(name, folder_path, correlation_id=cid), correlation_id=correlation_id)

    def revoke_guest_profile(self, profile_id: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("revoke_guest_profile", lambda cid: self._services.settings.revoke_guest_profile(profile_id, correlation_id=cid), correlation_id=correlation_id)

    def get_cluster_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_cluster_settings", lambda cid: self._services.settings.get_cluster(correlation_id=cid), correlation_id=correlation_id)

    def start_cluster_pairing(self, node_id: str | None = None, window_id: str | None = None, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("start_cluster_pairing", lambda cid: self._services.settings.start_cluster_pairing(node_id=node_id, window_id=window_id, correlation_id=cid), correlation_id=correlation_id)

    def confirm_cluster_pairing(self, matches: bool, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("confirm_cluster_pairing", lambda cid: self._services.settings.confirm_cluster_pairing(bool(matches), correlation_id=cid), correlation_id=correlation_id)

    def unlink_cluster_node(self, node_id: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("unlink_cluster_node", lambda cid: self._services.settings.unlink_cluster_node(node_id, correlation_id=cid), correlation_id=correlation_id)

    def unpair_cluster_local(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("unpair_cluster_local", lambda cid: self._services.settings.unpair_cluster_local(correlation_id=cid), correlation_id=correlation_id)

    def get_security_monitor_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_security_monitor_settings", lambda cid: self._services.settings.get_security_monitor(correlation_id=cid), correlation_id=correlation_id)

    def update_security_monitor_settings(self, values: dict, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("update_security_monitor_settings", lambda cid: self._services.settings.update_security_monitor(values, correlation_id=cid), correlation_id=correlation_id)

    def clear_security_monitor_history(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("clear_security_monitor_history", lambda cid: self._services.settings.clear_security_history(correlation_id=cid), correlation_id=correlation_id)

    def unblock_security_ip(self, ip: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("unblock_security_ip", lambda cid: self._services.settings.unblock_security_ip(ip, correlation_id=cid), correlation_id=correlation_id)

    def get_data_vault_intro(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_data_vault_intro", lambda cid: self._services.settings.get_data_vault_intro(correlation_id=cid), correlation_id=correlation_id)

    def mark_data_vault_intro_offered(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("mark_data_vault_intro_offered", lambda cid: self._services.settings.mark_data_vault_intro_offered(correlation_id=cid), correlation_id=correlation_id)

    def defer_data_vault_intro(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("defer_data_vault_intro", lambda cid: self._services.settings.defer_data_vault_intro(correlation_id=cid), correlation_id=correlation_id)

    def get_data_vault_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_data_vault_settings", lambda cid: self._services.settings.get_data_vault(correlation_id=cid), correlation_id=correlation_id)

    def configure_data_vault(self, mode: str, password: str = "", remember_on_windows: bool = False, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("configure_data_vault", lambda cid: self._services.settings.configure_data_vault(mode, password=password, remember_on_windows=remember_on_windows, correlation_id=cid), correlation_id=correlation_id)

    def unlock_data_vault(self, method: str, secret: str = "", correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("unlock_data_vault", lambda cid: self._services.settings.unlock_data_vault(method, secret=secret, correlation_id=cid), correlation_id=correlation_id)

    def generate_data_vault_recovery_key(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("generate_data_vault_recovery_key", lambda cid: self._services.settings.generate_data_vault_recovery_key(correlation_id=cid), correlation_id=correlation_id)

    def skip_data_vault_recovery_key(self, confirmed: bool = False, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("skip_data_vault_recovery_key", lambda cid: self._services.settings.skip_data_vault_recovery_key(bool(confirmed), correlation_id=cid), correlation_id=correlation_id)

    def set_data_vault_remember_on_windows(self, enabled: bool, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("set_data_vault_remember_on_windows", lambda cid: self._services.settings.set_data_vault_remember_on_windows(bool(enabled), correlation_id=cid), correlation_id=correlation_id)

    def change_data_vault_password(self, current_password: str, new_password: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("change_data_vault_password", lambda cid: self._services.settings.change_data_vault_password(current_password, new_password, correlation_id=cid), correlation_id=correlation_id)

    def change_data_vault_mode(self, mode: str, current_password: str = "", new_password: str = "", remember_on_windows: bool = False, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("change_data_vault_mode", lambda cid: self._services.settings.change_data_vault_mode(mode, current_password=current_password, new_password=new_password, remember_on_windows=remember_on_windows, correlation_id=cid), correlation_id=correlation_id)

    def reset_data_vault_password_with_recovery(self, recovery_key: str, new_password: str, remember_on_windows: bool = False, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("reset_data_vault_password_with_recovery", lambda cid: self._services.settings.reset_data_vault_password_with_recovery(recovery_key, new_password, remember_on_windows=remember_on_windows, correlation_id=cid), correlation_id=correlation_id)

    def get_history_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_history_settings", lambda cid: self._services.settings.get_history(correlation_id=cid), correlation_id=correlation_id)

    def get_updates_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_updates_settings", lambda cid: self._services.settings.get_updates(correlation_id=cid), correlation_id=correlation_id)

    def check_for_updates(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("check_for_updates", lambda cid: self._services.settings.check_updates(correlation_id=cid), correlation_id=correlation_id)

    def get_about_settings(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke("get_about_settings", lambda cid: self._services.settings.get_about(correlation_id=cid), correlation_id=correlation_id)

    def clear_cache_and_data(self, confirmed: bool = False, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "clear_cache_and_data",
            lambda cid: self._services.settings.clear_cache_and_data(confirmed, correlation_id=cid),
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Public sharing
    # ------------------------------------------------------------------
    def get_sharing_snapshot(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_sharing_snapshot",
            lambda cid: self._services.sharing.snapshot(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def list_web_sessions(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "list_web_sessions",
            lambda cid: self._services.sharing.list_web_sessions(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def update_public_sharing(
        self,
        community_browse_root: bool,
        community_download: bool,
        community_upload: bool,
        public_upload_mode: str,
        max_uploads_per_hour: int,
        max_upload_size_mb: int,
        allowed_upload_extensions: Sequence[str],
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "update_public_sharing",
            lambda cid: self._services.sharing.update_public_config(
                community_browse_root=bool(community_browse_root),
                community_download=bool(community_download),
                community_upload=bool(community_upload),
                public_upload_mode=public_upload_mode,
                max_uploads_per_hour=max_uploads_per_hour,
                max_upload_size_mb=max_upload_size_mb,
                allowed_upload_extensions=list(allowed_upload_extensions),
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def rotate_access_keys(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "rotate_access_keys",
            lambda cid: self._services.sharing.rotate_access_keys(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def generate_access_key(self, kind: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "generate_access_key",
            lambda cid: self._services.sharing.generate_access_key(kind, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def set_web_access(
        self,
        password: str,
        enabled: bool = True,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "set_web_access",
            lambda cid: self._services.sharing.set_web_access(
                password,
                enabled=bool(enabled),
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def generate_web_access_password(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "generate_web_access_password",
            lambda cid: self._services.sharing.generate_web_access_password(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def revoke_web_session(self, session_id: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "revoke_web_session",
            lambda cid: self._services.sharing.revoke_web_session(session_id, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def revoke_all_web_sessions(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "revoke_all_web_sessions",
            lambda cid: self._services.sharing.revoke_all_web_sessions(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def get_tunnel_status(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_tunnel_status",
            lambda cid: self._services.sharing.get_tunnel_status(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def start_tunnel(
        self,
        rotate_keys: bool = True,
        admin_password: str = "",
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "start_tunnel",
            lambda cid: self._services.sharing.start_tunnel(
                rotate_keys=bool(rotate_keys),
                admin_password=admin_password,
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    def stop_tunnel(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "stop_tunnel",
            lambda cid: self._services.sharing.stop_tunnel(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def get_cloudflare_status(self, hostname: str = "", correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_cloudflare_status",
            lambda cid: self._services.sharing.cloudflare_status(hostname, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def cloudflare_login(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "cloudflare_login",
            lambda cid: self._services.sharing.cloudflare_login(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def cloudflare_setup(
        self, hostname: str, port: int | None = None, correlation_id: str | None = None
    ) -> ApiResponse:
        return self._invoke(
            "cloudflare_setup",
            lambda cid: self._services.sharing.cloudflare_setup(
                hostname, port=port, correlation_id=cid
            ),
            correlation_id=correlation_id,
        )

    def start_cloudflare_tunnel(
        self, hostname: str, admin_password: str, correlation_id: str | None = None
    ) -> ApiResponse:
        return self._invoke(
            "start_cloudflare_tunnel",
            lambda cid: self._services.sharing.start_cloudflare_tunnel(
                hostname, admin_password, correlation_id=cid
            ),
            correlation_id=correlation_id,
        )

    def stop_cloudflare_tunnel(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "stop_cloudflare_tunnel",
            lambda cid: self._services.sharing.stop_cloudflare_tunnel(correlation_id=cid),
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Trusted devices
    # ------------------------------------------------------------------
    def list_trusted_devices(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "list_trusted_devices",
            lambda cid: self._services.devices.list_trusted_devices(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def get_pairing_snapshot(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_pairing_snapshot",
            lambda cid: self._services.devices.pairing_snapshot(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def start_pairing(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "start_pairing",
            lambda cid: self._services.devices.start_pairing(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def expire_pairing(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "expire_pairing",
            lambda cid: self._services.devices.expire_pairing(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def get_pairing_qr(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_pairing_qr",
            lambda cid: self._services.devices.pairing_qr(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def revoke_device(self, device_id: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "revoke_device",
            lambda cid: self._services.devices.revoke_device(device_id, correlation_id=cid),
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Activity
    # ------------------------------------------------------------------
    def get_activity_snapshot(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_activity_snapshot",
            lambda cid: self._services.activity.snapshot(correlation_id=cid),
            correlation_id=correlation_id,
        )

    def export_activity_logs(self, target_path: str, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "export_activity_logs",
            lambda cid: self._services.activity.export_logs(target_path, correlation_id=cid),
            correlation_id=correlation_id,
        )

    def resolve_upload(
        self,
        request_id: str,
        accepted: bool,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        return self._invoke(
            "resolve_upload",
            lambda cid: self._services.activity.resolve_upload(
                request_id,
                bool(accepted),
                correlation_id=cid,
            ),
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------
    def get_metrics_snapshot(self, correlation_id: str | None = None) -> ApiResponse:
        return self._invoke(
            "get_metrics_snapshot",
            lambda cid: self._services.metrics.snapshot(correlation_id=cid),
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Boundary machinery
    # ------------------------------------------------------------------
    def _invoke(
        self,
        operation: str,
        callback: Callable[[str], _T],
        *,
        correlation_id: str | None = None,
    ) -> ApiResponse:
        with correlation_scope(correlation_id) as cid:
            started = time.monotonic()
            self._emit_log(
                "desktop_api.called",
                operation=operation,
                status="started",
                correlation_id=cid,
            )
            try:
                data = callback(cid)
                self._assert_json_safe(data)
                response = self._success(data, cid)
                self._assert_json_safe(response)
            except ApplicationServiceError as error:
                response = self._application_error(operation, error, cid, started)
            except Exception as error:
                response = self._internal_error(operation, error, cid, started)
            else:
                self._emit_log(
                    "desktop_api.completed",
                    operation=operation,
                    status="success",
                    correlation_id=cid,
                    duration_ms=self._duration_ms(started),
                )
            return response

    @staticmethod
    def _success(data: Any, correlation_id: str) -> ApiResponse:
        return ApiResponse(
            ok=True,
            data=data,
            error=None,
            meta={"correlation_id": correlation_id},
        )

    def _application_error(
        self,
        operation: str,
        error: ApplicationServiceError,
        correlation_id: str,
        started: float,
    ) -> ApiResponse:
        cid = str(error.correlation_id or correlation_id)
        category = self._error_category(error)
        api_error = ApiError(
            code=str(error.code or "application_error"),
            category=category,
            message_key=str(error.code or "application_error"),
            details=self._safe_details(error.details),
        )
        response = ApiResponse(
            ok=False,
            data=None,
            error=api_error,
            meta={"correlation_id": cid},
        )
        self._emit_log(
            "desktop_api.error",
            level="warning" if category in {"validation", "not_found", "conflict"} else "error",
            operation=operation,
            status="failed",
            correlation_id=cid,
            error_type=type(error).__name__,
            error_code=api_error["code"],
            error_category=category,
            duration_ms=self._duration_ms(started),
        )
        return self._ensure_error_response_json_safe(response, correlation_id)

    def _internal_error(
        self,
        operation: str,
        error: Exception,
        correlation_id: str,
        started: float,
    ) -> ApiResponse:
        code = "desktop_api.serialization_failed" if isinstance(error, (TypeError, ValueError)) and "JSON" in str(error) else "desktop_api.internal"
        category = "serialization" if code.endswith("serialization_failed") else "internal"
        response = ApiResponse(
            ok=False,
            data=None,
            error=ApiError(
                code=code,
                category=category,
                message_key=code,
                details={},
            ),
            meta={"correlation_id": correlation_id},
        )
        self._emit_log(
            "desktop_api.error",
            level="error",
            operation=operation,
            status="failed",
            correlation_id=correlation_id,
            error_type=type(error).__name__,
            error_code=code,
            error_category=category,
            duration_ms=self._duration_ms(started),
        )
        return self._ensure_error_response_json_safe(response, correlation_id)

    @staticmethod
    def _error_category(error: ApplicationServiceError) -> str:
        if isinstance(error, ApplicationValidationError):
            return "validation"
        if isinstance(error, ApplicationNotFoundError):
            return "not_found"
        if isinstance(error, ApplicationConflictError):
            return "conflict"
        if isinstance(error, ApplicationUnavailableError):
            return "unavailable"
        if isinstance(error, ApplicationOperationError):
            return "operation"
        return "operation"

    @classmethod
    def _safe_details(cls, details: Mapping[str, Any] | None) -> dict[str, Any]:
        if not details:
            return {}
        result: dict[str, Any] = {}
        for key, value in details.items():
            result[str(key)] = cls._safe_detail_value(value, key=str(key))
        return result

    @classmethod
    def _safe_detail_value(cls, value: Any, *, key: str = "") -> Any:
        if is_sensitive_secret_name(key):
            return "<redacted>"
        if isinstance(value, str):
            return redact_secret_text(value)
        if value is None or isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, Mapping):
            return {str(k): cls._safe_detail_value(v, key=str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._safe_detail_value(item) for item in value]
        # Exception metadata is not part of the business payload contract.  A
        # string fallback guarantees the error envelope itself can never crash
        # a desktop shell because of an exotic details value.
        return "<unsupported>"

    @staticmethod
    def _assert_json_safe(value: Any) -> None:
        try:
            json.dumps(value, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise TypeError(f"DesktopApi payload is not JSON serializable: {error}") from error

    @classmethod
    def _ensure_error_response_json_safe(cls, response: ApiResponse, fallback_cid: str) -> ApiResponse:
        try:
            cls._assert_json_safe(response)
            return response
        except Exception:
            # Last-resort containment path: this object is made only of JSON
            # primitives and is intentionally independent of the failed error.
            return ApiResponse(
                ok=False,
                data=None,
                error=ApiError(
                    code="desktop_api.error_serialization_failed",
                    category="serialization",
                    message_key="desktop_api.error_serialization_failed",
                    details={},
                ),
                meta={"correlation_id": str(fallback_cid)},
            )

    def _emit_log(self, event: str, **fields: Any) -> None:
        """Observability must never become a new crash vector."""
        try:
            self._log.emit(event, **fields)
        except Exception:
            # The default StructuredLogger already uses failure-contained sinks,
            # but DesktopApi keeps this final guard for injected/test loggers.
            return

    @staticmethod
    def _duration_ms(started: float) -> float:
        return round((time.monotonic() - started) * 1000, 3)
