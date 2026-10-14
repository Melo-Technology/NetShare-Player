"""JSON-safe JS API bridge over the frozen DesktopApi and UiEventBus publisher."""

from __future__ import annotations

from collections.abc import Mapping
import json
import time
import webbrowser
from typing import Any

from src.application.correlation import correlation_scope, current_correlation_id, new_correlation_id
from src.desktop_api import DesktopApi
from src.ui_event_bus import EventPublisher, TOAST_REQUESTED
from src.ui_event_bus.events import (
    SERVER_STATUS_CHANGED, SERVER_ADDRESSES_CHANGED, SETTINGS_CHANGED,
    SHARING_CHANGED, DEVICES_CHANGED,
)

from .observability import build_shell_logger, safe_log

# Explicit allow-list.  PyWebView must never turn Python reflection into a public
# frontend API surface.  Every name below is a frozen Step 02 DesktopApi method.
DESKTOP_API_METHODS: frozenset[str] = frozenset(
    {
        "get_server_snapshot",
        "start_server",
        "stop_server",
        "get_connection_qr",
        "get_qr_code",
        "get_settings_snapshot",
        "update_appearance",
        "update_language",
        "update_advanced_visibility",
        "get_local_password_secret",
        "update_local_password",
        "update_password_reminder",
        "update_ffmpeg_path",
        "update_performance_preset",
        "update_worker_budget",
        "update_gpu_preference",
        "update_log_buffer_lines",
        "update_cluster_role",
        "update_hidden_path",
        "set_shared_roots",
        "clear_folder_history",
        "get_sharing_snapshot",
        "list_web_sessions",
        "update_public_sharing",
        "rotate_access_keys",
        "generate_access_key",
        "set_web_access",
        "generate_web_access_password",
        "revoke_web_session",
        "revoke_all_web_sessions",
        "get_tunnel_status",
        "start_tunnel",
        "stop_tunnel",
        "get_cloudflare_status",
        "cloudflare_login",
        "cloudflare_setup",
        "start_cloudflare_tunnel",
        "stop_cloudflare_tunnel",
        "list_trusted_devices",
        "get_pairing_snapshot",
        "start_pairing",
        "expire_pairing",
        "get_pairing_qr",
        "revoke_device",
        "get_activity_snapshot",
        "export_activity_logs",
        "resolve_upload",
        "get_metrics_snapshot",
        "get_permissions_settings",
        "update_permissions_settings",
        "set_transport_tls",
        "set_keep_awake",
        "rescan_media",
        "get_performance_details",
        "get_ffmpeg_details",
        "recheck_ffmpeg",
        "get_ffmpeg_install_plan",
        "install_ffmpeg",
        "get_premium_settings",
        "mark_premium_folder",
        "generate_premium_code",
        "revoke_premium_code",
        "get_cloud_settings",
        "connect_cloud",
        "reconnect_cloud",
        "forget_cloud_profile",
        "disconnect_cloud",
        "get_inbox_management",
        "open_inbox_folder",
        "export_transfer_report",
        "export_server_report",
        "get_folder_tree",
        "get_folder_children",
        "set_folder_visibility",
        "get_guest_profiles",
        "create_guest_profile",
        "revoke_guest_profile",
        "get_cluster_settings",
        "start_cluster_pairing",
        "confirm_cluster_pairing",
        "unlink_cluster_node",
        "unpair_cluster_local",
        "get_security_monitor_settings",
        "update_security_monitor_settings",
        "clear_security_monitor_history",
        "unblock_security_ip",
        "get_data_vault_intro",
        "mark_data_vault_intro_offered",
        "defer_data_vault_intro",
        "get_data_vault_settings",
        "configure_data_vault",
        "unlock_data_vault",
        "generate_data_vault_recovery_key",
        "skip_data_vault_recovery_key",
        "set_data_vault_remember_on_windows",
        "change_data_vault_password",
        "change_data_vault_mode",
        "reset_data_vault_password_with_recovery",
        "get_history_settings",
        "get_updates_settings",
        "check_for_updates",
        "get_about_settings",
        "clear_cache_and_data",
    }
)


class ShellBridge:
    """Object exposed to JavaScript as ``window.pywebview.api``.

    The bridge contains no business logic.  Calls are either shell diagnostics
    (``ping``/``probe_event``) or delegated to the frozen DesktopApi allow-list.
    Every public return value is JSON-safe without a custom encoder.
    """

    def __init__(
        self,
        desktop_api: DesktopApi,
        publisher: EventPublisher,
        *,
        logger: Any | None = None,
        frontend_ready_callback: Any | None = None,
    ) -> None:
        self._desktop_api = desktop_api
        self._publisher = publisher
        self._window = None
        self._webview_module = None
        self._frontend_ready_callback = frontend_ready_callback
        self._log = logger or build_shell_logger("ShellBridge")
        safe_log(
            self._log,
            "shell.bridge.initialized",
            operation="initialize",
            status="success",
        )

    def attach_window(self, window: Any, webview_module: Any | None = None) -> None:
        self._window = window
        self._webview_module = webview_module

    def frontend_ready(self, correlation_id: str | None = None) -> dict[str, Any]:
        """Signal that the hidden main document completed its initialization.

        The shell runtime uses this signal to keep the dedicated frameless splash
        visible until both the frontend is ready and the minimum splash duration
        has elapsed.  It carries no business state and remains JSON-safe.
        """
        with correlation_scope(correlation_id) as cid:
            started = time.perf_counter()
            try:
                callback = self._frontend_ready_callback
                if callable(callback):
                    callback()
                response = self._success({"frontend": "ready"}, cid)
                self._ensure_json_safe(response)
                safe_log(
                    self._log,
                    "shell.frontend.ready",
                    operation="frontend_ready",
                    status="success",
                    correlation_id=cid,
                    duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                )
                return response
            except Exception as exc:
                return self._contained_error("frontend_ready", exc, cid, started)

    def choose_folder(self, correlation_id: str | None = None) -> dict[str, Any]:
        with correlation_scope(correlation_id) as cid:
            started = time.perf_counter()
            try:
                if self._window is None:
                    return self._validation_error(
                        "choose_folder", code="desktop_shell.window_unavailable",
                        correlation_id=cid, started=started, details={}
                    )
                dialog_type = None
                module = self._webview_module
                enum = getattr(module, "FileDialog", None) if module is not None else None
                if enum is not None:
                    dialog_type = getattr(enum, "FOLDER", None)
                if dialog_type is None and module is not None:
                    dialog_type = getattr(module, "FOLDER_DIALOG", None)
                callback = getattr(self._window, "create_file_dialog", None)
                if not callable(callback):
                    return self._validation_error(
                        "choose_folder", code="desktop_shell.folder_dialog_unavailable",
                        correlation_id=cid, started=started, details={}
                    )
                if dialog_type is None:
                    result = callback()
                else:
                    result = callback(dialog_type, allow_multiple=False)
                path = None
                if isinstance(result, (list, tuple)) and result:
                    path = str(result[0])
                elif isinstance(result, str) and result:
                    path = result
                response = self._success({"path": path}, cid)
                self._ensure_json_safe(response)
                safe_log(self._log, "shell.dialog.folder", operation="choose_folder", status="selected" if path else "cancelled", correlation_id=cid, duration_ms=round((time.perf_counter()-started)*1000.0,3))
                return response
            except Exception as exc:
                return self._contained_error("choose_folder", exc, cid, started)

    def choose_save_file(self, suggested_name: str = "netshare-logs.txt", correlation_id: str | None = None) -> dict[str, Any]:
        with correlation_scope(correlation_id) as cid:
            started = time.perf_counter()
            try:
                if self._window is None:
                    return self._validation_error("choose_save_file", code="desktop_shell.window_unavailable", correlation_id=cid, started=started, details={})
                callback = getattr(self._window, "create_file_dialog", None)
                if not callable(callback):
                    return self._validation_error("choose_save_file", code="desktop_shell.file_dialog_unavailable", correlation_id=cid, started=started, details={})
                module=self._webview_module; dialog_type=None
                enum=getattr(module,"FileDialog",None) if module is not None else None
                if enum is not None: dialog_type=getattr(enum,"SAVE",None)
                if dialog_type is None and module is not None: dialog_type=getattr(module,"SAVE_DIALOG",None)
                kwargs={"save_filename": str(suggested_name or "netshare-logs.txt")}
                result=callback(dialog_type, **kwargs) if dialog_type is not None else callback(**kwargs)
                path=result[0] if isinstance(result,(list,tuple)) and result else result if isinstance(result,str) else None
                response=self._success({"path": str(path) if path else None},cid); self._ensure_json_safe(response); return response
            except Exception as exc:
                return self._contained_error("choose_save_file",exc,cid,started)

    def choose_file(self, correlation_id: str | None = None) -> dict[str, Any]:
        """Open a native single-file picker for Settings paths (e.g. FFmpeg)."""
        with correlation_scope(correlation_id) as cid:
            started = time.perf_counter()
            try:
                if self._window is None:
                    return self._validation_error("choose_file", code="desktop_shell.window_unavailable", correlation_id=cid, started=started, details={})
                callback = getattr(self._window, "create_file_dialog", None)
                if not callable(callback):
                    return self._validation_error("choose_file", code="desktop_shell.file_dialog_unavailable", correlation_id=cid, started=started, details={})
                module = self._webview_module
                dialog_type = None
                enum = getattr(module, "FileDialog", None) if module is not None else None
                if enum is not None:
                    dialog_type = getattr(enum, "OPEN", None)
                if dialog_type is None and module is not None:
                    dialog_type = getattr(module, "OPEN_DIALOG", None)
                result = callback(dialog_type, allow_multiple=False) if dialog_type is not None else callback(allow_multiple=False)
                path = result[0] if isinstance(result, (list, tuple)) and result else result if isinstance(result, str) else None
                response = self._success({"path": str(path) if path else None}, cid)
                self._ensure_json_safe(response)
                return response
            except Exception as exc:
                return self._contained_error("choose_file", exc, cid, started)

    def open_external_url(self, url: str, correlation_id: str | None = None) -> dict[str, Any]:
        """Open an explicit HTTPS support/documentation URL in the OS browser."""
        with correlation_scope(correlation_id) as cid:
            started = time.perf_counter()
            target = str(url or "").strip()
            if not target.lower().startswith("https://"):
                return self._validation_error(
                    "open_external_url", code="desktop_shell.external_url_invalid",
                    correlation_id=cid, started=started, details={}
                )
            try:
                opened = bool(webbrowser.open(target))
                response = self._success({"opened": opened}, cid)
                self._ensure_json_safe(response)
                safe_log(self._log, "shell.external_url.opened", operation="open_external_url",
                         status="success" if opened else "failed", correlation_id=cid,
                         duration_ms=round((time.perf_counter()-started)*1000.0,3))
                return response
            except Exception as exc:
                return self._contained_error("open_external_url", exc, cid, started)

    def ping(self, correlation_id: str | None = None) -> dict[str, Any]:
        """Validate the JS → Python → DesktopApi round-trip without exposing data."""
        with correlation_scope(correlation_id) as cid:
            started = time.perf_counter()
            safe_log(
                self._log,
                "shell.bridge.called",
                operation="ping",
                status="started",
                correlation_id=cid,
            )
            try:
                response = self._desktop_api.get_server_snapshot(correlation_id=cid)
                if not bool(response.get("ok")):
                    self._ensure_json_safe(response)
                    safe_log(
                        self._log,
                        "shell.bridge.completed",
                        operation="ping",
                        status="failed",
                        correlation_id=str(response.get("meta", {}).get("correlation_id") or cid),
                        duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                    )
                    return response
                result = self._success(
                    {
                        "bridge": "ready",
                        "desktop_api": "ready",
                    },
                    cid,
                )
                self._ensure_json_safe(result)
                safe_log(
                    self._log,
                    "shell.bridge.completed",
                    operation="ping",
                    status="success",
                    correlation_id=cid,
                    duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                )
                return result
            except Exception as exc:
                return self._contained_error("ping", exc, cid, started)

    def call_api(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Delegate an allow-listed call to DesktopApi.

        ``params`` is required to be a plain JSON-compatible object.  The shell
        never reaches Application Services or core objects directly.
        """
        with correlation_scope(correlation_id) as cid:
            started = time.perf_counter()
            operation = str(method or "").strip()
            safe_log(
                self._log,
                "shell.bridge.called",
                operation=operation or "call_api",
                status="started",
                correlation_id=cid,
            )
            try:
                if operation not in DESKTOP_API_METHODS:
                    return self._validation_error(
                        operation or "call_api",
                        code="desktop_shell.method_not_allowed",
                        correlation_id=cid,
                        started=started,
                        details={"method": operation},
                    )
                if params is None:
                    arguments: dict[str, Any] = {}
                elif isinstance(params, Mapping):
                    arguments = dict(params)
                else:
                    return self._validation_error(
                        operation or "call_api",
                        code="desktop_shell.params_invalid",
                        correlation_id=cid,
                        started=started,
                        details={},
                    )

                if "correlation_id" in arguments:
                    return self._validation_error(
                        operation or "call_api",
                        code="desktop_shell.correlation_reserved",
                        correlation_id=cid,
                        started=started,
                        details={},
                    )
                self._ensure_json_safe(arguments)

                callback = getattr(self._desktop_api, operation)
                response = callback(**arguments, correlation_id=cid)
                self._ensure_json_safe(response)
                if response.get("ok"):
                    self._publish_api_side_effects(operation, response, cid)
                safe_log(
                    self._log,
                    "shell.bridge.completed",
                    operation=operation,
                    status="success" if response.get("ok") else "failed",
                    correlation_id=str(response.get("meta", {}).get("correlation_id") or cid),
                    duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                )
                return response
            except TypeError as exc:
                # Signature mismatch is a caller validation issue, not a Python crash.
                result = self._error(
                    code="desktop_shell.arguments_invalid",
                    category="validation",
                    correlation_id=cid,
                    details={},
                )
                safe_log(
                    self._log,
                    "shell.bridge.error",
                    operation=operation or "call_api",
                    status="failed",
                    level="warning",
                    correlation_id=cid,
                    error_type=type(exc).__name__,
                    error_code="desktop_shell.arguments_invalid",
                    duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                )
                return result
            except Exception as exc:
                return self._contained_error(operation or "call_api", exc, cid, started)

    def probe_event(self, correlation_id: str | None = None) -> dict[str, Any]:
        """Publish a non-business diagnostic event through the frozen UiEventBus."""
        with correlation_scope(correlation_id) as cid:
            started = time.perf_counter()
            try:
                accepted = self._publisher.publish(
                    TOAST_REQUESTED,
                    {
                        "level": "info",
                        "message_key": "shell.bridge.probe",
                        "params": {"probe": cid},
                    },
                    correlation_id=cid,
                )
                result = self._success({"accepted": bool(accepted)}, cid)
                self._ensure_json_safe(result)
                safe_log(
                    self._log,
                    "shell.event.probe_published",
                    operation="probe_event",
                    status="success" if accepted else "dropped",
                    correlation_id=cid,
                    duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                )
                return result
            except Exception as exc:
                return self._contained_error("probe_event", exc, cid, started)

    def _publish_api_side_effects(self, operation: str, response: dict[str, Any], correlation_id: str) -> None:
        try:
            data = response.get("data") if isinstance(response, dict) else None
            if operation in {"start_server", "stop_server"} and isinstance(data, dict):
                running = bool(data.get("server_running"))
                self._publisher.publish(SERVER_STATUS_CHANGED, {"running": running}, correlation_id=correlation_id)
                addresses = list(data.get("network_addresses") or []) if running else []
                self._publisher.publish(SERVER_ADDRESSES_CHANGED, {"addresses": [str(v) for v in addresses]}, correlation_id=correlation_id)
            elif operation in {
                "update_appearance", "update_language", "update_advanced_visibility", "update_local_password",
                "update_password_reminder", "update_ffmpeg_path", "update_performance_preset", "update_worker_budget",
                "update_gpu_preference", "update_log_buffer_lines", "update_cluster_role",
                "update_hidden_path", "set_shared_roots", "clear_folder_history",
                "update_permissions_settings", "set_transport_tls", "set_keep_awake", "rescan_media", "recheck_ffmpeg",
                "mark_premium_folder", "generate_premium_code", "revoke_premium_code",
                "connect_cloud", "reconnect_cloud", "forget_cloud_profile", "disconnect_cloud", "set_folder_visibility",
                "create_guest_profile", "revoke_guest_profile", "start_cluster_pairing",
                "confirm_cluster_pairing", "unlink_cluster_node", "unpair_cluster_local",
            }:
                self._publisher.publish(SETTINGS_CHANGED, {"section": "settings", "reason": operation}, correlation_id=correlation_id)
            elif operation in {"update_public_sharing", "rotate_access_keys", "generate_access_key", "set_web_access", "generate_web_access_password", "revoke_web_session", "revoke_all_web_sessions", "start_tunnel", "stop_tunnel", "cloudflare_login", "cloudflare_setup", "start_cloudflare_tunnel", "stop_cloudflare_tunnel"}:
                self._publisher.publish(SHARING_CHANGED, {"reason": operation}, correlation_id=correlation_id)
            elif operation in {"revoke_device", "start_pairing", "expire_pairing"}:
                self._publisher.publish(DEVICES_CHANGED, {"reason": operation}, correlation_id=correlation_id)
        except Exception as exc:
            safe_log(self._log, "shell.event.publish_failed", operation=operation, status="failed", level="warning", correlation_id=correlation_id, error_type=type(exc).__name__)

    @staticmethod
    def _success(data: Any, correlation_id: str) -> dict[str, Any]:
        return {
            "ok": True,
            "data": data,
            "error": None,
            "meta": {"correlation_id": correlation_id},
        }

    @staticmethod
    def _error(
        *,
        code: str,
        category: str,
        correlation_id: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "data": None,
            "error": {
                "code": code,
                "category": category,
                "message_key": code,
                "details": details,
            },
            "meta": {"correlation_id": correlation_id},
        }


    def _validation_error(
        self,
        operation: str,
        *,
        code: str,
        correlation_id: str,
        started: float,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        result = self._error(
            code=code,
            category="validation",
            correlation_id=correlation_id,
            details=details,
        )
        safe_log(
            self._log,
            "shell.bridge.error",
            operation=operation,
            status="failed",
            level="warning",
            correlation_id=correlation_id,
            error_code=code,
            error_category="validation",
            duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
        )
        return result

    def _contained_error(
        self,
        operation: str,
        error: Exception,
        correlation_id: str,
        started: float,
    ) -> dict[str, Any]:
        result = self._error(
            code="desktop_shell.internal",
            category="internal",
            correlation_id=correlation_id,
            details={},
        )
        safe_log(
            self._log,
            "shell.bridge.error",
            operation=operation,
            status="failed",
            level="error",
            correlation_id=correlation_id,
            error_type=type(error).__name__,
            error_code="desktop_shell.internal",
            duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
        )
        return result

    @staticmethod
    def _ensure_json_safe(value: Any) -> None:
        json.dumps(value, allow_nan=False)
