"""Application service for persisted settings already owned by ``src.state``."""

from __future__ import annotations

from ..adapters import StateAdapter
from ..adapters.settings_features_adapter import CloudFeatureError, SettingsFeaturesAdapter
from ..dto import SettingsSnapshotDTO, WorkerBudgetDTO
from ..exceptions import (
    ApplicationConflictError,
    ApplicationUnavailableError,
    ApplicationValidationError,
)
from .base import BaseApplicationService


class SettingsService(BaseApplicationService):
    service_name = "settings"

    def __init__(self, state: StateAdapter | None = None, logger=None, runtime_controller=None, features: SettingsFeaturesAdapter | None = None):
        self.state = state or StateAdapter()
        self.features = features or SettingsFeaturesAdapter()
        if runtime_controller is None:
            from src.runtime.server_runtime import server_runtime_controller
            runtime_controller = server_runtime_controller
        self.runtime_controller = runtime_controller
        super().__init__(logger)

    def snapshot(self, *, correlation_id: str | None = None) -> SettingsSnapshotDTO:
        return self._execute("snapshot", self._snapshot, correlation_id=correlation_id)

    def _snapshot(self) -> SettingsSnapshotDTO:
        return SettingsSnapshotDTO(**self.state.settings_values())

    def update_appearance(self, *, theme: str | None = None, text_size: str | None = None, correlation_id=None) -> SettingsSnapshotDTO:
        if theme is None and text_size is None:
            self._validation_error("update_appearance", ApplicationValidationError("no appearance setting supplied", code="settings.appearance.empty"), correlation_id=correlation_id)
        def apply():
            self.state.save_appearance(theme=theme, text_size=text_size)
            self.log.emit("settings.updated", operation="update_appearance", status="success", settings=[name for name, value in (("theme", theme), ("text_size", text_size)) if value is not None])
            return self._snapshot()
        return self._execute("update_appearance", apply, correlation_id=correlation_id)

    def update_language(self, language: str, *, correlation_id=None) -> SettingsSnapshotDTO:
        if not str(language or "").strip():
            self._validation_error("update_language", ApplicationValidationError("language is required", code="settings.language.required"), field="language", correlation_id=correlation_id)
        return self._update("update_language", lambda: self.state.save_language(language), ["language"], correlation_id)

    def update_advanced_visibility(self, enabled: bool, *, correlation_id=None) -> SettingsSnapshotDTO:
        return self._update("update_advanced_visibility", lambda: self.state.save_show_advanced_settings(bool(enabled)), ["show_advanced_settings"], correlation_id)

    def get_local_password_secret(self, *, correlation_id=None) -> dict:
        def load():
            secret = self.state.local_password_secret()
            return {"configured": bool(secret), "password": secret}
        return self._execute("get_local_password_secret", load, correlation_id=correlation_id)

    def update_local_password(self, password: str, *, reminder_days: int | None = None, correlation_id=None) -> SettingsSnapshotDTO:
        value = str(password if password is not None else "")
        if len(value) > 128:
            self._validation_error("update_local_password", ApplicationValidationError("password too long", code="settings.password.too_long"), field="password", correlation_id=correlation_id)
        if value and len(value) < 8:
            self._validation_error("update_local_password", ApplicationValidationError("password too short", code="settings.password.too_short"), field="password", correlation_id=correlation_id)
        if value != value.strip():
            self._validation_error("update_local_password", ApplicationValidationError("password may not start or end with whitespace", code="settings.password.whitespace"), field="password", correlation_id=correlation_id)
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            self._validation_error("update_local_password", ApplicationValidationError("password contains control characters", code="settings.password.invalid_characters"), field="password", correlation_id=correlation_id)
        if reminder_days is not None:
            try:
                days = int(reminder_days)
            except (TypeError, ValueError):
                self._validation_error("update_local_password", ApplicationValidationError("invalid reminder duration", code="settings.password_reminder.invalid"), field="reminder_days", correlation_id=correlation_id)
            if not 1 <= days <= 3650:
                self._validation_error("update_local_password", ApplicationValidationError("reminder duration out of range", code="settings.password_reminder.out_of_range"), field="reminder_days", correlation_id=correlation_id)
        def apply():
            if reminder_days is not None:
                self.state.save_password_reminder_days(int(reminder_days))
            self.state.save_local_password(value)
            self.state.clear_local_password_auth_failures()
            self.log.emit("settings.updated", operation="update_local_password", status="success", settings=["local_password", "password_reminder_days"] if reminder_days is not None else ["local_password"], credential_changed=True)
            return self._snapshot()
        return self._execute("update_local_password", apply, correlation_id=correlation_id)

    def update_password_reminder(self, reminder_days: int, *, correlation_id=None) -> SettingsSnapshotDTO:
        try:
            days = int(reminder_days)
        except (TypeError, ValueError):
            self._validation_error("update_password_reminder", ApplicationValidationError("invalid reminder duration", code="settings.password_reminder.invalid"), field="reminder_days", correlation_id=correlation_id)
        if not 1 <= days <= 3650:
            self._validation_error("update_password_reminder", ApplicationValidationError("reminder duration out of range", code="settings.password_reminder.out_of_range"), field="reminder_days", correlation_id=correlation_id)
        return self._update("update_password_reminder", lambda: self.state.save_password_reminder_days(days), ["password_reminder_days"], correlation_id)

    def update_ffmpeg_path(self, path: str, *, correlation_id=None) -> SettingsSnapshotDTO:
        return self._update("update_ffmpeg_path", lambda: self.state.save_ffmpeg_path(path), ["ffmpeg_path"], correlation_id)

    def update_performance_preset(self, preset: str, *, correlation_id=None) -> SettingsSnapshotDTO:
        return self._update("update_performance_preset", lambda: self.state.save_performance_preset(preset), ["performance_preset", "index_workers", "analysis_workers"], correlation_id)

    def update_worker_budget(self, index_workers: object, analysis_workers: object, *, changed: str, correlation_id=None) -> WorkerBudgetDTO:
        if changed not in {"index", "analysis"}:
            self._validation_error("update_worker_budget", ApplicationValidationError("changed must be index or analysis", code="settings.worker_budget.changed_invalid"), field="changed", correlation_id=correlation_id)
        def apply():
            budget = self.state.save_worker_budget(index_workers, analysis_workers, changed=changed)
            self.log.emit("settings.updated", operation="update_worker_budget", status="success", settings=["index_workers", "analysis_workers"])
            return WorkerBudgetDTO(
                cpu_count_logical=int(budget.cpu_count_logical), hard_total=int(budget.hard_total),
                index_workers=int(budget.index_workers), analysis_workers=int(budget.analysis_workers),
                adjusted=budget.adjusted,
            )
        return self._execute("update_worker_budget", apply, correlation_id=correlation_id)

    def update_gpu_preference(self, preference: str, *, capabilities=None, correlation_id=None) -> SettingsSnapshotDTO:
        return self._update("update_gpu_preference", lambda: self.state.save_gpu_encoder_preference(preference, capabilities=capabilities), ["gpu_encoder_preference"], correlation_id)

    def update_log_buffer_lines(self, value: object, *, correlation_id=None) -> SettingsSnapshotDTO:
        return self._update("update_log_buffer_lines", lambda: self.state.save_log_buffer_lines(value), ["log_buffer_lines"], correlation_id)

    def update_cluster_role(self, role: str, *, correlation_id=None) -> SettingsSnapshotDTO:
        return self._update("update_cluster_role", lambda: self.state.save_cluster_role(role), ["cluster_role"], correlation_id)

    def update_hidden_path(self, slot: str, relative_path: str, hidden: bool, *, correlation_id=None) -> bool:
        def apply():
            changed = self.state.set_hidden_path(slot, relative_path, bool(hidden))
            if changed:
                self.log.emit("settings.updated", operation="update_hidden_path", status="success", settings=["hidden_paths"], root_slot=slot)
            return bool(changed)
        return self._execute("update_hidden_path", apply, correlation_id=correlation_id)

    def set_shared_roots(self, paths, *, persist: bool = True, correlation_id=None):
        def apply():
            if self.runtime_controller.is_running():
                roots = self.runtime_controller.replace_shared_roots(paths, persist=persist)
            else:
                roots = self.state.set_shared_roots(paths, persist=persist)
            self.log.emit("settings.updated", operation="set_shared_roots", status="success", settings=["shared_roots"], root_count=len(roots))
            return [str(root.path) for root in roots]
        return self._execute("set_shared_roots", apply, correlation_id=correlation_id)

    def clear_folder_history(self, *, correlation_id=None) -> None:
        def apply():
            self.state.clear_folder_share_history()
            self.log.emit("settings.updated", operation="clear_folder_history", status="success", settings=["folder_share_history"])
        return self._execute("clear_folder_history", apply, correlation_id=correlation_id)


    # ------------------------------------------------------------------
    # Settings feature snapshots / actions used by the WebView Settings UI
    # ------------------------------------------------------------------
    def get_permissions(self, *, correlation_id=None):
        return self._execute("get_permissions", self.features.permissions_snapshot, correlation_id=correlation_id)

    def update_permissions(self, *, port=None, server_name=None, allow_upload=None, allow_edit=None, correlation_id=None):
        if port is not None:
            try:
                parsed = int(port)
            except (TypeError, ValueError):
                self._validation_error("update_permissions", ApplicationValidationError("invalid port", code="settings.port.invalid"), field="port", correlation_id=correlation_id)
            if not 1 <= parsed <= 65532:
                self._validation_error("update_permissions", ApplicationValidationError("port out of range", code="settings.port.out_of_range"), field="port", correlation_id=correlation_id)
        def apply():
            result = self.features.update_permissions(port=port, server_name=server_name, allow_upload=allow_upload, allow_edit=allow_edit)
            self.log.emit("settings.updated", operation="update_permissions", status="success", settings=[k for k,v in (("port",port),("server_name",server_name),("allow_upload",allow_upload),("allow_edit",allow_edit)) if v is not None])
            return self.features.permissions_snapshot()
        return self._execute("update_permissions", apply, correlation_id=correlation_id)

    def set_transport_tls(self, enabled: bool, *, correlation_id=None):
        def apply():
            try:
                result = self.features.set_transport_tls(bool(enabled))
            except PermissionError as error:
                raise ApplicationConflictError(
                    str(error), code="settings.transport_tls.environment_override"
                ) from error
            restarted = False
            if self.runtime_controller.is_running():
                self.runtime_controller.restart()
                restarted = True
            current = self.features.permissions_snapshot()["transport_tls"]
            self.log.emit(
                "settings.updated", operation="set_transport_tls", status="success",
                settings=["transport_tls"], restarted=restarted,
            )
            return {**current, "restarted": restarted}
        return self._execute("set_transport_tls", apply, correlation_id=correlation_id)

    def set_keep_awake(self, enabled: bool, *, correlation_id=None):
        return self._feature_mutation("set_keep_awake", ["keep_awake"], lambda: self.features.set_keep_awake(bool(enabled)), correlation_id)

    def rescan_media(self, *, correlation_id=None):
        return self._feature_mutation("rescan_media", ["media_index"], lambda: (self.features.rescan_media(), {"started": True})[1], correlation_id)

    def get_performance_details(self, *, correlation_id=None):
        return self._execute("get_performance_details", self.features.performance_snapshot, correlation_id=correlation_id)

    def get_ffmpeg_details(self, *, correlation_id=None):
        return self._execute("get_ffmpeg_details", self.features.ffmpeg_snapshot, correlation_id=correlation_id)

    def recheck_ffmpeg(self, path: str, *, correlation_id=None):
        return self._feature_mutation("recheck_ffmpeg", ["ffmpeg_path", "ffmpeg_capabilities"], lambda: self.features.recheck_ffmpeg(path), correlation_id)

    def get_ffmpeg_install_plan(self, *, correlation_id=None):
        return self._execute("get_ffmpeg_install_plan", self.features.ffmpeg_install_plan, correlation_id=correlation_id)

    def install_ffmpeg(self, *, correlation_id=None):
        return self._execute("install_ffmpeg", self.features.install_ffmpeg, correlation_id=correlation_id)

    def get_premium(self, *, correlation_id=None):
        return self._execute("get_premium", lambda: self._vault_call(self.features.premium_snapshot), correlation_id=correlation_id)

    def mark_premium_folder(self, path: str, label: str, price_note: str = "", *, correlation_id=None):
        if not str(path or "").strip() or not str(label or "").strip():
            self._validation_error("mark_premium_folder", ApplicationValidationError("path and label required", code="settings.premium.required"), correlation_id=correlation_id)
        return self._feature_mutation("mark_premium_folder", ["premium_folders"], lambda: self._vault_call(lambda: {"marked": self.features.mark_premium_absolute(path, label, price_note)}), correlation_id)

    def generate_premium_code(self, folder_path: str, *, correlation_id=None):
        return self._feature_mutation("generate_premium_code", ["premium_codes"], lambda: self._vault_call(lambda: self.features.generate_premium_code(folder_path)), correlation_id)

    def revoke_premium_code(self, code_id: int, *, correlation_id=None):
        return self._feature_mutation("revoke_premium_code", ["premium_codes"], lambda: self._vault_call(lambda: {"revoked": self.features.revoke_premium_code(code_id)}), correlation_id)

    def get_cloud(self, *, correlation_id=None):
        return self._execute("get_cloud", lambda: self._vault_call(self.features.cloud_snapshot), correlation_id=correlation_id)

    def connect_cloud(self, provider: str, *, client_id: str = "", client_secret: str = "", app_key: str = "", email: str = "", password: str = "", correlation_id=None):
        provider = str(provider or "").strip().lower()
        def apply():
            try:
                if provider == "drive":
                    if not client_id.strip(): raise ApplicationValidationError("client id required", code="settings.cloud.client_id_required")
                    return self.features.connect_drive(client_id, client_secret) if str(client_secret or "").strip() else self.features.connect_drive(client_id)
                if provider == "dropbox":
                    if not app_key.strip(): raise ApplicationValidationError("app key required", code="settings.cloud.app_key_required")
                    return self.features.connect_dropbox(app_key)
                if provider == "mega":
                    if not email.strip() or not password: raise ApplicationValidationError("credentials required", code="settings.cloud.credentials_required")
                    return self.features.connect_mega(email, password)
                raise ApplicationValidationError("unknown provider", code="settings.cloud.provider_invalid")
            except CloudFeatureError as error:
                details = {
                    "provider": error.provider,
                    "provider_code": error.code,
                    "provider_message": str(error)[:300],
                    **{
                        str(key): value
                        for key, value in error.details.items()
                        if key in {"http_status", "provider_code"}
                        and isinstance(value, (str, int, float, bool))
                    },
                }
                self.log.emit(
                    "settings.cloud_provider_failed",
                    level="error",
                    operation="connect_cloud",
                    status="failed",
                    provider=error.provider,
                    provider_error_code=error.code,
                    provider_message=str(error)[:300],
                    provider_http_status=details.get("http_status"),
                )
                raise ApplicationUnavailableError(
                    "cloud provider connection failed",
                    code=f"settings.cloud.{error.code}",
                    details=details,
                ) from error
        return self._feature_mutation("connect_cloud", ["cloud_accounts"], lambda: self._vault_call(apply), correlation_id)

    def reconnect_cloud(self, profile_id: str, *, password: str = "", correlation_id=None):
        clean_profile = str(profile_id or "").strip()
        if not clean_profile:
            self._validation_error(
                "reconnect_cloud",
                ApplicationValidationError("profile id required", code="settings.cloud.profile_required"),
                correlation_id=correlation_id,
            )

        def apply():
            try:
                return self.features.reconnect_cloud(clean_profile, password=password)
            except CloudFeatureError as error:
                details = {
                    "provider": error.provider,
                    "provider_code": error.code,
                    "provider_message": str(error)[:300],
                    **{
                        str(key): value
                        for key, value in error.details.items()
                        if key in {"http_status", "provider_code"}
                        and isinstance(value, (str, int, float, bool))
                    },
                }
                raise ApplicationUnavailableError(
                    "cloud provider connection failed",
                    code=f"settings.cloud.{error.code}",
                    details=details,
                ) from error
            except ValueError as error:
                code = str(error)
                if code == "cloud_profile_password_required":
                    raise ApplicationValidationError("password required", code="settings.cloud.credentials_required") from error
                if code == "cloud_profile_not_found":
                    raise ApplicationValidationError("saved connector not found", code="settings.cloud.profile_not_found") from error
                raise ApplicationValidationError("saved connector invalid", code="settings.cloud.profile_invalid") from error

        return self._feature_mutation("reconnect_cloud", ["cloud_accounts"], lambda: self._vault_call(apply), correlation_id)

    def forget_cloud_profile(self, profile_id: str, *, correlation_id=None):
        clean_profile = str(profile_id or "").strip()
        if not clean_profile:
            self._validation_error("forget_cloud_profile", ApplicationValidationError("profile id required", code="settings.cloud.profile_required"), correlation_id=correlation_id)
        return self._feature_mutation("forget_cloud_profile", ["cloud_accounts"], lambda: self._vault_call(lambda: {"forgotten": self.features.forget_cloud_profile(clean_profile)}), correlation_id)

    def disconnect_cloud(self, provider_id: str, account_id: str, *, correlation_id=None):
        return self._feature_mutation("disconnect_cloud", ["cloud_accounts"], lambda: self._vault_call(lambda: {"disconnected": self.features.disconnect_cloud(provider_id, account_id)}), correlation_id)

    def _vault_call(self, callback):
        from src.core.data_vault import (
            VaultAuthenticationError, VaultCorruptedError, VaultLockedError, VaultUnavailableError,
        )
        try:
            return callback()
        except VaultAuthenticationError as error:
            raise ApplicationValidationError("vault authentication failed", code=str(error)) from error
        except VaultLockedError as error:
            raise ApplicationConflictError("vault is locked", code=str(error)) from error
        except VaultCorruptedError as error:
            raise ApplicationConflictError("vault data is corrupted", code=str(error)) from error
        except VaultUnavailableError as error:
            raise ApplicationUnavailableError("vault protection unavailable", code=str(error)) from error

    def get_data_vault_intro(self, *, correlation_id=None):
        return self._execute("get_data_vault_intro", self.features.data_vault_intro_snapshot, correlation_id=correlation_id)

    def mark_data_vault_intro_offered(self, *, correlation_id=None):
        return self._feature_mutation("mark_data_vault_intro_offered", ["data_vault_prompt"], self.features.mark_data_vault_intro_offered, correlation_id)

    def defer_data_vault_intro(self, *, correlation_id=None):
        return self._feature_mutation("defer_data_vault_intro", ["data_vault_prompt"], self.features.defer_data_vault_intro, correlation_id)

    def get_data_vault(self, *, correlation_id=None):
        return self._execute("get_data_vault", self.features.data_vault_snapshot, correlation_id=correlation_id)

    def configure_data_vault(self, mode: str, *, password: str = "", remember_on_windows: bool = False, correlation_id=None):
        from src.runtime.server_runtime import server_runtime_controller
        if server_runtime_controller.is_running():
            raise ApplicationConflictError(
                "stop the server before configuring the data vault",
                code="settings.vault.server_must_be_stopped",
            )
        clean_mode = str(mode or "").strip().lower()
        if clean_mode not in {"os", "password"}:
            self._validation_error("configure_data_vault", ApplicationValidationError("invalid vault mode", code="settings.vault.mode_invalid"), field="mode", correlation_id=correlation_id)
        if clean_mode == "password" and len(str(password or "")) < 8:
            self._validation_error("configure_data_vault", ApplicationValidationError("password too short", code="settings.vault.password_too_short"), field="password", correlation_id=correlation_id)
        return self._feature_mutation(
            "configure_data_vault", ["data_vault"],
            lambda: self._vault_call(lambda: self.features.configure_data_vault(clean_mode, str(password or ""), bool(remember_on_windows))),
            correlation_id,
        )

    def unlock_data_vault(self, method: str, *, secret: str = "", correlation_id=None):
        return self._feature_mutation(
            "unlock_data_vault", ["data_vault"],
            lambda: self._vault_call(lambda: self.features.unlock_data_vault(str(method or ""), str(secret or ""))),
            correlation_id,
        )

    def generate_data_vault_recovery_key(self, *, correlation_id=None):
        return self._feature_mutation(
            "generate_data_vault_recovery_key", ["data_vault"],
            lambda: self._vault_call(self.features.generate_data_vault_recovery_key),
            correlation_id,
        )

    def skip_data_vault_recovery_key(self, confirmed: bool, *, correlation_id=None):
        if not confirmed:
            self._validation_error("skip_data_vault_recovery_key", ApplicationValidationError("explicit confirmation required", code="settings.vault.recovery_skip_confirmation_required"), field="confirmed", correlation_id=correlation_id)
        return self._feature_mutation(
            "skip_data_vault_recovery_key", ["data_vault"],
            lambda: self._vault_call(self.features.skip_data_vault_recovery_key),
            correlation_id,
        )

    def set_data_vault_remember_on_windows(self, enabled: bool, *, correlation_id=None):
        return self._feature_mutation(
            "set_data_vault_remember_on_windows", ["data_vault"],
            lambda: self._vault_call(lambda: self.features.set_data_vault_remember_on_windows(bool(enabled))),
            correlation_id,
        )

    def change_data_vault_password(self, current_password: str, new_password: str, *, correlation_id=None):
        if len(str(new_password or "")) < 8:
            self._validation_error("change_data_vault_password", ApplicationValidationError("password too short", code="settings.vault.password_too_short"), field="new_password", correlation_id=correlation_id)
        return self._feature_mutation(
            "change_data_vault_password", ["data_vault"],
            lambda: self._vault_call(lambda: self.features.change_data_vault_password(str(current_password or ""), str(new_password or ""))),
            correlation_id,
        )

    def change_data_vault_mode(self, mode: str, *, current_password: str = "", new_password: str = "", remember_on_windows: bool = False, correlation_id=None):
        clean_mode = str(mode or "").strip().lower()
        if clean_mode not in {"os", "password"}:
            self._validation_error("change_data_vault_mode", ApplicationValidationError("invalid vault mode", code="settings.vault.mode_invalid"), field="mode", correlation_id=correlation_id)
        if clean_mode == "password" and len(str(new_password or "")) < 8:
            self._validation_error("change_data_vault_mode", ApplicationValidationError("password too short", code="settings.vault.password_too_short"), field="new_password", correlation_id=correlation_id)
        return self._feature_mutation(
            "change_data_vault_mode", ["data_vault"],
            lambda: self._vault_call(lambda: self.features.change_data_vault_mode(clean_mode, current_password=str(current_password or ""), new_password=str(new_password or ""), remember_on_windows=bool(remember_on_windows))),
            correlation_id,
        )

    def reset_data_vault_password_with_recovery(self, recovery_key: str, new_password: str, *, remember_on_windows: bool = False, correlation_id=None):
        if len(str(new_password or "")) < 8:
            self._validation_error("reset_data_vault_password_with_recovery", ApplicationValidationError("password too short", code="settings.vault.password_too_short"), field="new_password", correlation_id=correlation_id)
        return self._feature_mutation(
            "reset_data_vault_password_with_recovery", ["data_vault"],
            lambda: self._vault_call(lambda: self.features.reset_data_vault_password_with_recovery(str(recovery_key or ""), str(new_password or ""), bool(remember_on_windows))),
            correlation_id,
        )

    def get_inbox_management(self, *, correlation_id=None):
        return self._execute("get_inbox_management", lambda: self._vault_call(self.features.inbox_management_snapshot), correlation_id=correlation_id)

    def open_inbox_folder(self, *, correlation_id=None):
        return self._execute("open_inbox_folder", self.features.open_inbox_folder, correlation_id=correlation_id)

    def export_transfer_report(self, target_path: str, *, correlation_id=None):
        clean = str(target_path or "").strip()
        if not clean:
            self._validation_error("export_transfer_report", ApplicationValidationError("target path required", code="settings.transfer_report.path_required"), field="target_path", correlation_id=correlation_id)
        return self._execute("export_transfer_report", lambda: self._vault_call(lambda: self.features.export_transfer_report(clean)), correlation_id=correlation_id)

    def export_server_report(self, target_path: str, *, correlation_id=None):
        clean = str(target_path or "").strip()
        if not clean:
            self._validation_error("export_server_report", ApplicationValidationError("target path required", code="settings.server_report.path_required"), field="target_path", correlation_id=correlation_id)
        return self._execute("export_server_report", lambda: self._vault_call(lambda: self.features.export_server_report(clean)), correlation_id=correlation_id)

    def get_folder_tree(self, *, correlation_id=None):
        return self._execute("get_folder_tree", lambda: self._vault_call(self.features.folder_tree), correlation_id=correlation_id)

    def get_folder_children(self, path: str, *, correlation_id=None):
        return self._execute("get_folder_children", lambda: self._vault_call(lambda: self.features.folder_children(path)), correlation_id=correlation_id)

    def set_folder_visibility(self, path: str, hidden: bool, *, correlation_id=None):
        return self._feature_mutation("set_folder_visibility", ["hidden_paths"], lambda: self._vault_call(lambda: self.features.set_folder_visibility(path, hidden)), correlation_id)

    def get_guest_profiles(self, *, correlation_id=None):
        return self._execute("get_guest_profiles", lambda: self._vault_call(self.features.guest_profiles_snapshot), correlation_id=correlation_id)

    def create_guest_profile(self, name: str, folder_path: str, *, correlation_id=None):
        return self._feature_mutation("create_guest_profile", ["guest_profiles"], lambda: self._vault_call(lambda: self.features.create_guest_profile_from_absolute(name, folder_path)), correlation_id)

    def revoke_guest_profile(self, profile_id: str, *, correlation_id=None):
        return self._feature_mutation("revoke_guest_profile", ["guest_profiles"], lambda: self._vault_call(lambda: {"revoked": self.features.revoke_guest_profile(profile_id)}), correlation_id)

    def get_cluster(self, *, correlation_id=None):
        return self._execute("get_cluster", self.features.cluster_snapshot, correlation_id=correlation_id)

    def start_cluster_pairing(self, *, node_id=None, window_id=None, correlation_id=None):
        return self._feature_mutation("start_cluster_pairing", ["cluster_pairing"], lambda: self.features.cluster_start_pairing(node_id, window_id), correlation_id)

    def confirm_cluster_pairing(self, matches: bool, *, correlation_id=None):
        return self._feature_mutation("confirm_cluster_pairing", ["cluster_pairing", "cluster_nodes"], lambda: self.features.cluster_confirm_pairing(matches), correlation_id)

    def unlink_cluster_node(self, node_id: str, *, correlation_id=None):
        return self._feature_mutation("unlink_cluster_node", ["cluster_nodes"], lambda: self.features.cluster_unlink_node(node_id), correlation_id)

    def unpair_cluster_local(self, *, correlation_id=None):
        return self._feature_mutation("unpair_cluster_local", ["cluster_pairing", "cluster_nodes"], self.features.cluster_unpair_local, correlation_id)

    def get_security_monitor(self, *, correlation_id=None):
        return self._execute("get_security_monitor", lambda: self._vault_call(self.features.security_snapshot), correlation_id=correlation_id)

    def update_security_monitor(self, values: dict, *, correlation_id=None):
        if not isinstance(values, dict):
            self._validation_error("update_security_monitor", ApplicationValidationError("configuration object required", code="settings.security.invalid"), field="values", correlation_id=correlation_id)
        allowed = {"enabled", "notify", "block_mode", "auth_failures", "auth_window_seconds", "block_seconds", "burst_requests", "burst_window_seconds", "route_misses", "route_window_seconds"}
        unknown = set(values) - allowed
        if unknown:
            self._validation_error("update_security_monitor", ApplicationValidationError("unknown security setting", code="settings.security.unknown", details={"keys": sorted(unknown)}), field="values", correlation_id=correlation_id)
        return self._feature_mutation("update_security_monitor", ["security_monitor"], lambda: self._vault_call(lambda: self.features.update_security_monitor(dict(values))), correlation_id)

    def clear_security_history(self, *, correlation_id=None):
        return self._feature_mutation("clear_security_history", ["security_monitor_history"], lambda: self._vault_call(self.features.clear_security_history), correlation_id)

    def unblock_security_ip(self, ip: str, *, correlation_id=None):
        clean = str(ip or "").strip()
        if not clean or len(clean) > 96:
            self._validation_error("unblock_security_ip", ApplicationValidationError("invalid IP", code="settings.security.ip_invalid"), field="ip", correlation_id=correlation_id)
        return self._feature_mutation("unblock_security_ip", ["security_monitor_blocks"], lambda: self._vault_call(lambda: self.features.unblock_security_ip(clean)), correlation_id)

    def get_history(self, *, correlation_id=None):
        return self._execute("get_history", lambda: self._vault_call(self.features.history_snapshot), correlation_id=correlation_id)

    def get_updates(self, *, correlation_id=None):
        return self._execute("get_updates", self.features.updates_snapshot, correlation_id=correlation_id)

    def check_updates(self, *, correlation_id=None):
        return self._execute("check_updates", self.features.check_updates, correlation_id=correlation_id)

    def get_about(self, *, correlation_id=None):
        return self._execute("get_about", self.features.about_snapshot, correlation_id=correlation_id)

    def clear_cache_and_data(self, confirmed: bool, *, correlation_id=None):
        if confirmed is not True:
            self._validation_error(
                "clear_cache_and_data",
                ApplicationValidationError(
                    "explicit confirmation required",
                    code="settings.maintenance.confirmation_required",
                ),
                field="confirmed",
                correlation_id=correlation_id,
            )

        def apply():
            try:
                result = self.features.clear_cache_and_data()
            except Exception as error:
                from src.core.local_data_reset import LocalDataResetBusyError
                if isinstance(error, LocalDataResetBusyError):
                    raise ApplicationConflictError(
                        "active clients or transfers prevent reset",
                        code="settings.maintenance.busy",
                        details={"activity": dict(error.activity)},
                    ) from error
                raise
            self.log.emit(
                "settings.local_data_cleared",
                level="warning",
                operation="clear_cache_and_data",
                status="success",
                actor="local_desktop_ui",
                settings=["regenerable_cache", "sqlite_local_data"],
                preserved=list(result.get("preserved") or []),
            )
            return result

        return self._execute("clear_cache_and_data", apply, correlation_id=correlation_id)

    def _feature_mutation(self, operation, settings, callback, correlation_id):
        def apply():
            result = callback()
            self.log.emit("settings.updated", operation=operation, status="success", settings=list(settings))
            return result
        return self._execute(operation, apply, correlation_id=correlation_id)

    def _update(self, operation, callback, settings, correlation_id):
        def apply():
            callback()
            self.log.emit("settings.updated", operation=operation, status="success", settings=settings)
            return self._snapshot()
        return self._execute(operation, apply, correlation_id=correlation_id)
