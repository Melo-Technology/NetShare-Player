"""Thin adapters for Settings capabilities that already exist in the core.

No business rules are reimplemented here.  The adapter converts existing core/runtime
objects into JSON-native values for Application Services.
"""
from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
from typing import Any

import src.deps as deps
import src.state as state
from src.constants import VERSION
from src.runtime.ffmpeg_install_runtime import ffmpeg_install_runtime
from src.runtime.permissions_runtime import permissions_runtime_controller
from src.runtime.premium_runtime import premium_runtime_controller
from src.runtime.remote_flags_runtime import remote_flags_runtime_controller
from src.runtime.update_runtime import update_runtime_controller


class CloudFeatureError(RuntimeError):
    """Sanitised provider error crossing the core -> application adapter."""

    def __init__(self, provider: str, code: str, message: str, details: dict | None = None):
        self.provider = str(provider)
        self.code = str(code or "provider_error")
        self.details = dict(details or {})
        super().__init__(str(message or self.code))


class SettingsFeaturesAdapter:
    def __init__(self) -> None:
        # Application-adapter boundary is the earliest layer allowed to touch
        # core reset persistence.  Complete any crash-interrupted reset before
        # Settings/DesktopApi can expose SQLite-backed state.  Failures leave
        # the HTTP maintenance gate closed and are surfaced by subsequent
        # operations rather than bypassing shell architecture boundaries.
        try:
            from src.core.local_data_reset import recover_interrupted_reset
            self._reset_recovery = recover_interrupted_reset()
            self._reset_recovery_error = None
        except Exception as exc:
            self._reset_recovery = None
            self._reset_recovery_error = f"{type(exc).__name__}: {exc}"

    def _require_vault_ready(self) -> None:
        """Retry transparent unlock, then fail closed if protected state is locked."""
        from src.core.data_vault import VaultLockedError, get_data_vault
        vault = get_data_vault(state._CONFIG_DIR)
        if vault.configured and not vault.unlocked:
            retry = getattr(state, "try_auto_unlock_data_vault", None)
            if callable(retry):
                retry()
        if vault.configured and not vault.unlocked:
            raise VaultLockedError("vault_locked")

    def data_vault_intro_snapshot(self) -> dict[str, Any]:
        from src.core.data_vault import get_data_vault
        vault = get_data_vault(state._CONFIG_DIR)
        prompt = state.data_vault_prompt_snapshot()
        if vault.configured and prompt["state"] != "configured":
            state.save_data_vault_prompt_state("configured")
            prompt = state.data_vault_prompt_snapshot()
        return {
            **prompt,
            "configured": bool(vault.configured),
            "should_offer": bool(not vault.configured and prompt["state"] in {"never_configured", "offered"}),
        }

    def mark_data_vault_intro_offered(self) -> dict[str, Any]:
        if state.DATA_VAULT_PROMPT_STATE == "never_configured":
            state.save_data_vault_prompt_state("offered")
        return self.data_vault_intro_snapshot()

    def defer_data_vault_intro(self) -> dict[str, Any]:
        from src.core.data_vault import get_data_vault
        if not get_data_vault(state._CONFIG_DIR).configured:
            state.save_data_vault_prompt_state("deferred")
        return self.data_vault_intro_snapshot()

    def data_vault_snapshot(self) -> dict[str, Any]:
        from src.core.data_vault import get_data_vault, os_protection_available
        vault = get_data_vault(state._CONFIG_DIR)
        if vault.configured and not vault.unlocked:
            retry = getattr(state, "try_auto_unlock_data_vault", None)
            if callable(retry):
                retry()
        status = vault.status()
        from src.core.data_vault_migration import (
            MIGRATION_VERSION, migration_snapshot, start_migration_if_needed,
        )
        if status.configured and status.unlocked and vault.migration_version < MIGRATION_VERSION:
            start_migration_if_needed()
        return {
            "configured": bool(status.configured),
            "mode": str(status.mode),
            "unlocked": bool(status.unlocked),
            "remember_on_windows": bool(status.remember_on_windows),
            "recovery_enabled": bool(status.recovery_enabled),
            "recovery_decision": str(vault.recovery_decision),
            "os_protection_available": os_protection_available(state._CONFIG_DIR),
            "protected_scope": [
                "thumbnails", "waveforms", "web_sessions", "unlock_codes",
                "transfer_history", "security_history", "sensitive_metadata",
                "cloud_token_key",
            ],
            "migration": migration_snapshot(),
        }

    def configure_data_vault(self, mode: str, password: str = "", remember_on_windows: bool = False) -> dict[str, Any]:
        from src.core.data_vault import VaultUnavailableError, get_data_vault, os_protection_available
        vault = get_data_vault(state._CONFIG_DIR)
        clean_mode = str(mode or "").strip().lower()
        needs_os_store = clean_mode == "os" or (clean_mode == "password" and bool(remember_on_windows))
        if needs_os_store and not os_protection_available(state._CONFIG_DIR, force=True):
            raise VaultUnavailableError("os_protection_unavailable")
        if clean_mode == "os":
            vault.configure_os_protected()
        elif clean_mode == "password":
            vault.configure_password(str(password or ""), remember_on_windows=bool(remember_on_windows))
        else:
            raise ValueError("vault_mode_invalid")
        state.save_data_vault_prompt_state("configured")
        from src.core.data_vault_migration import start_migration_if_needed
        start_migration_if_needed()
        return self.data_vault_snapshot()

    def unlock_data_vault(self, method: str, secret: str = "") -> dict[str, Any]:
        from src.core.data_vault import get_data_vault
        vault = get_data_vault(state._CONFIG_DIR)
        method = str(method or "").strip().lower()
        if method == "os":
            vault.unlock_os()
        elif method == "password":
            vault.unlock_password(str(secret or ""))
        elif method == "recovery":
            vault.unlock_recovery(str(secret or ""))
        elif method == "remembered":
            if not vault.try_unlock_remembered():
                raise ValueError("vault_remembered_unlock_unavailable")
        else:
            raise ValueError("vault_unlock_method_invalid")
        if not state.reload_protected_vault_state():
            raise ValueError("vault_protected_state_reload_failed")
        from src.core.data_vault_migration import start_migration_if_needed
        start_migration_if_needed()
        return self.data_vault_snapshot()

    def generate_data_vault_recovery_key(self) -> dict[str, Any]:
        from src.core.data_vault import get_data_vault
        vault = get_data_vault(state._CONFIG_DIR)
        phrase = vault.generate_recovery_key_once()
        return {"recovery_key": phrase, "vault": self.data_vault_snapshot()}

    def skip_data_vault_recovery_key(self) -> dict[str, Any]:
        from src.core.data_vault import get_data_vault
        get_data_vault(state._CONFIG_DIR).skip_recovery_key()
        return self.data_vault_snapshot()

    def set_data_vault_remember_on_windows(self, enabled: bool) -> dict[str, Any]:
        from src.core.data_vault import VaultUnavailableError, get_data_vault, os_protection_available
        if bool(enabled) and not os_protection_available(state._CONFIG_DIR, force=True):
            raise VaultUnavailableError("os_protection_unavailable")
        get_data_vault(state._CONFIG_DIR).set_remember_on_windows(bool(enabled))
        return self.data_vault_snapshot()

    def change_data_vault_password(self, current_password: str, new_password: str) -> dict[str, Any]:
        from src.core.data_vault import get_data_vault
        get_data_vault(state._CONFIG_DIR).change_password(str(current_password or ""), str(new_password or ""))
        return self.data_vault_snapshot()

    def change_data_vault_mode(
        self, mode: str, *, current_password: str = "", new_password: str = "", remember_on_windows: bool = False
    ) -> dict[str, Any]:
        from src.core.data_vault import VaultUnavailableError, get_data_vault, os_protection_available
        vault = get_data_vault(state._CONFIG_DIR)
        clean_mode = str(mode or "").strip().lower()
        needs_os_store = clean_mode == "os" or (clean_mode == "password" and bool(remember_on_windows))
        if needs_os_store and not os_protection_available(state._CONFIG_DIR, force=True):
            raise VaultUnavailableError("os_protection_unavailable")
        if clean_mode == "os":
            vault.switch_to_os_protected(current_password=str(current_password or "") or None)
        elif clean_mode == "password":
            vault.switch_to_password(
                str(new_password or ""),
                current_password=str(current_password or "") or None,
                remember_on_windows=bool(remember_on_windows),
            )
        else:
            raise ValueError("vault_mode_invalid")
        return self.data_vault_snapshot()

    def reset_data_vault_password_with_recovery(
        self, recovery_key: str, new_password: str, remember_on_windows: bool = False
    ) -> dict[str, Any]:
        from src.core.data_vault import VaultUnavailableError, get_data_vault, os_protection_available
        if bool(remember_on_windows) and not os_protection_available(state._CONFIG_DIR, force=True):
            raise VaultUnavailableError("os_protection_unavailable")
        get_data_vault(state._CONFIG_DIR).reset_password_with_recovery(
            str(recovery_key or ""), str(new_password or ""), remember_on_windows=bool(remember_on_windows)
        )
        if not state.reload_protected_vault_state():
            raise ValueError("vault_protected_state_reload_failed")
        from src.core.data_vault_migration import start_migration_if_needed
        start_migration_if_needed()
        return self.data_vault_snapshot()

    def permissions_snapshot(self) -> dict[str, Any]:
        runtime = permissions_runtime_controller.snapshot()
        from src.core.file_index import _file_index
        from src.core.server_tls import tls_settings_snapshot
        profile = _file_index.profile
        return {
            **runtime,
            "transport_tls": tls_settings_snapshot(state._CONFIG_DIR),
            "remote_flags": remote_flags_runtime_controller.snapshot(),
            "hardware_profile": {
                "name": str(profile.name),
                "workers": int(profile.workers),
                "nvidia_detected": bool(profile.nvidia_detected),
                "nvidia_name": str(profile.nvidia_name) if profile.nvidia_name else None,
            },
        }

    def update_permissions(self, **values: Any) -> dict[str, Any]:
        return permissions_runtime_controller.update(**values)

    def set_transport_tls(self, enabled: bool) -> dict[str, Any]:
        from src.core.server_tls import (
            ServerTlsIdentityStore,
            save_tls_enabled,
            tls_environment_override,
        )
        if tls_environment_override() is not None:
            raise PermissionError("transport TLS is controlled by NETSHARE_TLS_ENABLED")
        if bool(enabled):
            # Validate/generate the full persistent identity before any live
            # listener is stopped. A failure therefore leaves the current
            # transport untouched rather than falling back to clear HTTP.
            ServerTlsIdentityStore(state._CONFIG_DIR).ensure_identity(state.SERVER_ID)
        save_tls_enabled(state._CONFIG_DIR, bool(enabled))
        return self.permissions_snapshot()["transport_tls"]

    def set_keep_awake(self, enabled: bool) -> dict[str, Any]:
        return permissions_runtime_controller.set_keep_awake(bool(enabled))

    def rescan_media(self) -> None:
        from src.core.file_index import _file_index
        _file_index.rescan_media(state.ROOT_DIR)

    def performance_snapshot(self) -> dict[str, Any]:
        from src.core.adaptive_streaming import (
            _system_total_memory_bytes,
            automatic_performance_preset,
            performance_policy,
        )
        from src.core.performance_resources import effective_worker_budget, hard_worker_total
        total_memory = _system_total_memory_bytes()
        cpu_count = max(1, int(os.cpu_count() or 1))
        selected = state.PERFORMANCE_PRESET or automatic_performance_preset(total_memory)
        budget = effective_worker_budget(selected, cpu_count, state.INDEX_WORKERS, state.ANALYSIS_WORKERS)
        policy = performance_policy(selected, total_memory)
        caps = deps.FFMPEG_CAPABILITIES
        gpu = []
        for backend in ("nvenc", "qsv", "amf", "videotoolbox"):
            status = caps.gpu_encoders.get(backend)
            gpu.append({
                "backend": backend,
                "declared": bool(status.declared) if status else False,
                "verified": bool(status.verified) if status else False,
                "failure_reason": str(status.failure_reason) if status and status.failure_reason else None,
                "device_name": str(status.device_name) if status and status.device_name else None,
            })
        return {
            "total_memory_bytes": int(total_memory) if total_memory is not None else None,
            "cpu_count": cpu_count,
            "detected_preset": automatic_performance_preset(total_memory),
            "selected_preset": selected,
            "worker_budget": {
                "cpu_count_logical": int(budget.cpu_count_logical),
                "hard_total": int(budget.hard_total),
                "index_workers": int(budget.index_workers),
                "analysis_workers": int(budget.analysis_workers),
                "adjusted": budget.adjusted,
            },
            "worker_hard_total": int(hard_worker_total(cpu_count)),
            "policy": {key: value for key, value in policy.items()},
            "gpu_preference": str(state.GPU_ENCODER_PREFERENCE),
            "gpu_backends": gpu,
            "log_buffer_lines": int(state.LOG_BUFFER_LINES),
        }

    def ffmpeg_snapshot(self) -> dict[str, Any]:
        caps = deps.FFMPEG_CAPABILITIES
        return {
            "configured_path": str(state.FFMPEG_PATH),
            "detected_path": str(deps.FFMPEG_BIN) if deps.FFMPEG_BIN else None,
            "ffprobe_path": str(deps.FFPROBE_BIN) if deps.FFPROBE_BIN else None,
            "source": str(deps.FFMPEG_SOURCE),
            "manual_path_invalid": bool(deps.FFMPEG_MANUAL_PATH_INVALID),
            "manual_path_error": str(deps.FFMPEG_MANUAL_PATH_ERROR) if deps.FFMPEG_MANUAL_PATH_ERROR else None,
            "available": bool(caps.available),
            "h264_encoder": str(caps.h264_encoder) if caps.h264_encoder else None,
            "hls_transcoding": bool(caps.hls_transcoding),
            "hls_transcoding_gpu": bool(caps.hls_transcoding_gpu),
            "audio_analysis": bool(caps.audio_analysis),
            "video_thumbnails": bool(caps.video_thumbnails),
            "error": str(caps.error) if caps.error else None,
            "gpu_encoders": [
                {
                    "backend": str(name),
                    "encoder": str(cap.encoder),
                    "declared": bool(cap.declared),
                    "verified": bool(cap.verified),
                    "failure_reason": str(cap.failure_reason) if cap.failure_reason else None,
                    "device_name": str(cap.device_name) if cap.device_name else None,
                }
                for name, cap in caps.gpu_encoders.items()
            ],
        }

    def recheck_ffmpeg(self, configured_path: str) -> dict[str, Any]:
        state.save_ffmpeg_path(str(configured_path or ""))
        deps.refresh_ffmpeg_capabilities(str(configured_path or ""), force_gpu_probe=True)
        return self.ffmpeg_snapshot()

    def ffmpeg_install_plan(self) -> dict[str, Any]:
        return ffmpeg_install_runtime.plan().to_dict()

    def install_ffmpeg(self) -> dict[str, Any]:
        return ffmpeg_install_runtime.launch()

    def premium_snapshot(self) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core import unlock_codes
        # Folder-marker discovery can require a full walk of large shared roots.
        # Return the parent roots and any cached result immediately while the
        # shared runtime refreshes marker discovery in the background.
        snapshot = premium_runtime_controller.snapshot()
        snapshot["codes"] = [dict(item) for item in unlock_codes.list_codes()]
        return snapshot

    def mark_premium_absolute(self, path: str, label: str, price_note: str = "") -> bool:
        self._require_vault_ready()
        from src.core import unlock_codes
        root = Path(state.ROOT_DIR).resolve()
        chosen = Path(path).resolve()
        relative = "/" + chosen.relative_to(root).as_posix()
        marked = bool(unlock_codes.mark_premium_folder(relative, label, price_note))
        if marked:
            premium_runtime_controller.invalidate()
        return marked

    def generate_premium_code(self, folder_path: str) -> dict[str, Any] | None:
        self._require_vault_ready()
        from src.core import unlock_codes
        value = unlock_codes.generate_code(folder_path)
        return dict(value) if value else None

    def revoke_premium_code(self, code_id: int) -> bool:
        self._require_vault_ready()
        from src.core import unlock_codes
        return bool(unlock_codes.revoke_code(int(code_id)))

    def cloud_snapshot(self) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.cloud import get_manager
        from src.core.cloud import dropbox as dropbox_mod
        from src.core.cloud import mega as mega_mod
        from src.core.cloud.profile_store import get_profile_store

        accounts = [dict(item) for item in get_manager().connected_accounts()]
        connected_keys = {
            (str(item.get("provider_id") or ""), str(item.get("account_id") or ""))
            for item in accounts
        }
        profile_store = get_profile_store()
        profiles = []
        for item in profile_store.list_metadata():
            value = dict(item)
            value["connected"] = (
                str(value.get("provider_id") or ""), str(value.get("account_id") or "")
            ) in connected_keys
            profiles.append(value)
        return {
            "accounts": accounts,
            "saved_profiles": profiles,
            "secure_profile_storage": profile_store.storage_info(),
            "providers": {
                "drive": {"available": bool(deps.HAS_REQUESTS)},
                "dropbox": {
                    "available": bool(deps.HAS_REQUESTS),
                    "redirect_uri": str(dropbox_mod.DROPBOX_REDIRECT_URI),
                },
                "mega": {"available": bool(mega_mod.is_available()), "message": str(mega_mod.unavailable_message()) if not mega_mod.is_available() else ""},
            },
        }

    def connect_drive(self, client_id: str, client_secret: str = "") -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.cloud import drive, get_manager, CloudProviderError
        clean_client_id = str(client_id).strip()
        clean_client_secret = str(client_secret or "").strip()
        try:
            token_data = (
                drive.connect(clean_client_id, client_secret=clean_client_secret)
                if clean_client_secret
                else drive.connect(clean_client_id)
            )
        except CloudProviderError as error:
            raise CloudFeatureError(
                "drive", error.code, str(error), getattr(error, "details", {}),
            ) from error
        account_id = token_data.get("label") or str(client_id).strip()
        label = str(token_data.get("label") or account_id)
        get_manager().register_account("drive", account_id, token_data)
        from src.core.cloud.profile_store import get_profile_store
        profile_id = ""
        try:
            profile = get_profile_store().save(
                "drive", str(account_id), label,
                {"client_id": clean_client_id, "client_secret": clean_client_secret},
            )
            profile_id = str(profile.get("profile_id") or "")
        except Exception:
            pass
        return {"provider_id": "drive", "account_id": str(account_id), "label": label}

    def connect_dropbox(self, app_key: str) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.cloud import dropbox, get_manager, CloudProviderError
        try:
            token_data = dropbox.connect(str(app_key).strip())
        except CloudProviderError as error:
            raise CloudFeatureError(
                "dropbox", error.code, str(error), getattr(error, "details", {}),
            ) from error
        # Dropbox returns a stable account_id in the token response.  Prefer it
        # over the human label/app key so reconnects and multiple accounts do not
        # alias each other merely because a display label changed.
        clean_app_key = str(app_key).strip()
        account_id = token_data.get("account_id") or token_data.get("label") or clean_app_key
        label = str(token_data.get("label") or account_id)
        get_manager().register_account("dropbox", account_id, token_data)
        from src.core.cloud.profile_store import get_profile_store
        profile_id = ""
        try:
            profile = get_profile_store().save(
                "dropbox", str(account_id), label, {"app_key": clean_app_key}
            )
            profile_id = str(profile.get("profile_id") or "")
        except Exception:
            pass
        return {"provider_id": "dropbox", "account_id": str(account_id), "label": label}

    def connect_mega(self, email: str, password: str) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.cloud import mega, get_manager, CloudProviderError
        clean_email = str(email).strip()
        try:
            token_data = mega.connect(clean_email, str(password))
        except CloudProviderError as error:
            raise CloudFeatureError(
                "mega", error.code, str(error), getattr(error, "details", {}),
            ) from error
        get_manager().register_account("mega", clean_email, token_data)
        from src.core.cloud.profile_store import get_profile_store
        profile_id = ""
        try:
            profile = get_profile_store().save(
                "mega", clean_email, clean_email, {"email": clean_email}
            )
            profile_id = str(profile.get("profile_id") or "")
        except Exception:
            pass
        return {"provider_id": "mega", "account_id": clean_email, "label": clean_email}

    def reconnect_cloud(self, profile_id: str, password: str = "") -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.cloud.profile_store import get_profile_store
        profile = get_profile_store().get(str(profile_id))
        if not profile:
            raise ValueError("cloud_profile_not_found")
        provider = str(profile.get("provider_id") or "").lower()
        config = dict(profile.get("config") or {})
        if provider == "drive":
            return self.connect_drive(
                str(config.get("client_id") or ""),
                str(config.get("client_secret") or ""),
            )
        if provider == "dropbox":
            return self.connect_dropbox(str(config.get("app_key") or ""))
        if provider == "mega":
            if not password:
                raise ValueError("cloud_profile_password_required")
            return self.connect_mega(str(config.get("email") or profile.get("account_id") or ""), str(password))
        raise ValueError("cloud_profile_unknown_provider")

    def forget_cloud_profile(self, profile_id: str) -> bool:
        self._require_vault_ready()
        from src.core.cloud.profile_store import get_profile_store
        return bool(get_profile_store().delete(str(profile_id)))

    def disconnect_cloud(self, provider_id: str, account_id: str) -> bool:
        self._require_vault_ready()
        from src.core.cloud import get_manager
        return bool(get_manager().disconnect(str(provider_id), str(account_id)))

    def inbox_management_snapshot(self) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.inbox import InboxService
        service = InboxService(state.INBOX_DIR, state.INBOX_HISTORY_PATH)
        return {
            "recent_files": [dict(item) for item in service.recent_items(5)],
            "history": [dict(item) for item in service.history()],
            "history_capacity": dict(service.history_capacity()),
        }

    def open_inbox_folder(self) -> dict[str, Any]:
        import os
        import subprocess
        import sys
        path = Path(state.INBOX_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
        return {"opened": True}

    def export_transfer_report(self, target_path: str) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.report_exports import export_transfer_report
        target = export_transfer_report(target_path)
        return {"path": str(target)}

    def export_server_report(self, target_path: str) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.report_exports import export_server_report
        target = export_server_report(target_path)
        return {"path": str(target)}

    def folder_tree(self) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.folder_visibility import folder_tree
        value = folder_tree()
        return {"items": [dict(item) for item in value.get("items", [])], "hidden": [dict(item) for item in value.get("hidden", [])]}

    def folder_children(self, requested: str) -> list[dict[str, Any]]:
        self._require_vault_ready()
        from src.core.folder_visibility import folder_children
        return [dict(item) for item in folder_children(str(requested))]

    def set_folder_visibility(self, requested: str, hidden: bool) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.folder_visibility import set_folder_visibility
        return dict(set_folder_visibility(str(requested), bool(hidden)))

    def guest_profiles_snapshot(self) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.guest_profiles import get_guest_profile_store
        store = get_guest_profile_store(state.GUEST_PROFILES_PATH)
        return {"profiles": [dict(item) for item in store.list()]}

    def create_guest_profile_from_absolute(self, name: str, selected: str) -> dict[str, Any]:
        self._require_vault_ready()
        from src.core.guest_profiles import get_guest_profile_store
        chosen = Path(selected).resolve()
        identity = None
        for shared_root in state.SHARED_ROOTS:
            try:
                relative = "/" + chosen.relative_to(shared_root.path.resolve()).as_posix()
                identity = {"root_slot": shared_root.slot, "path": relative}
                break
            except ValueError:
                continue
        if identity is None:
            raise ValueError("guest_profile_path_outside_shared_roots")
        return dict(get_guest_profile_store(state.GUEST_PROFILES_PATH).create(str(name), [identity]))

    def revoke_guest_profile(self, profile_id: str) -> bool:
        self._require_vault_ready()
        from src.core.guest_profiles import get_guest_profile_store
        return bool(get_guest_profile_store(state.GUEST_PROFILES_PATH).revoke(str(profile_id)))

    def cluster_snapshot(self) -> dict[str, Any]:
        from src.core.cluster.key_store import security_availability
        status = security_availability(state._CONFIG_DIR)
        manager = getattr(state, "_cluster_runtime", None)
        runtime = getattr(manager, "runtime", None) if manager is not None else None
        result: dict[str, Any] = {
            "role": str(state.CLUSTER_ROLE),
            "effective_role": str(state.effective_cluster_role()),
            "security": {"available": bool(status.available), "reason_code": str(status.reason_code or "")},
            "feature_enabled": state.FEATURE_FLAGS.get("cluster") is True,
            "running": runtime is not None,
            "pairing_targets": [],
            "nearby_nodes": [],
            "nodes": [],
            "max_slaves": 5,
            "slave_count": 0,
            "available_slots": 5,
            "active_pairing_target": {},
            "sas": "",
            "pairing_error": "",
            "pairing_active": False,
            "pairing_decided": False,
            "slave_paired": False,
            "failover_ready": False,
            "leader_node_id": "",
            "leader_epoch": 0,
            "failover_mode": "inactive",
        }
        # Persisted cluster state must remain visible even while the main server
        # (and therefore the cluster runtime) is stopped.  This keeps the
        # Co-Servers screen useful on desktop instead of hiding every link /
        # unlink control behind `running == true`.
        try:
            from src.core.cluster.identity import joined_slave_files_exist
            from src.core.cluster.registry import ClusterRegistry
            effective_role = state.effective_cluster_role()
            if effective_role == "slave" or state.CLUSTER_ROLE in ("slave", "auto"):
                result["slave_paired"] = bool(joined_slave_files_exist(state._CONFIG_DIR))
            if effective_role == "master" or state.CLUSTER_ROLE in ("master", "auto"):
                registry = ClusterRegistry(state._CONFIG_DIR / "cluster" / "nodes.json")
                result["nodes"] = [
                    {"node_id": str(node.node_id), "name": str(node.name), "online": False}
                    for node in registry.nodes
                ]
                result["slave_count"] = len(registry.nodes)
                result["available_slots"] = max(0, result["max_slaves"] - result["slave_count"])
        except Exception:
            # Snapshot rendering must never make Settings unusable just because
            # a stale/malformed cluster persistence file cannot be inspected.
            pass

        if runtime is None:
            return result
        authority = getattr(runtime, "failover_authority", None)
        if authority is not None:
            try:
                result["failover_ready"] = bool(authority.ready)
                result["leader_node_id"] = str(authority.leader_node_id or "")
                result["leader_epoch"] = int(authority.leader_epoch or 0)
                if result["effective_role"] == "master":
                    result["failover_mode"] = "leader"
                elif result["effective_role"] == "slave" and result["failover_ready"]:
                    result["failover_mode"] = "standby"
            except Exception:
                pass
        ceremony = getattr(runtime, "ceremony", None)
        result["sas"] = str(getattr(ceremony, "sas", "") or "")
        result["pairing_active"] = bool(ceremony is not None and not bool(getattr(ceremony, "closed", False)))
        result["pairing_decided"] = bool(ceremony is not None and getattr(ceremony, "_decision", None) is not None)
        result["pairing_error"] = str(getattr(runtime, "pairing_error", "") or "")
        targets = getattr(runtime, "pairing_targets", None)
        if callable(targets):
            payload = targets() or {}
            result["pairing_targets"] = [dict(item) for item in payload.get("targets", [])]
            capacity = dict(payload.get("capacity") or {})
            if capacity:
                result["max_slaves"] = int(capacity.get("maximum", result["max_slaves"]))
                result["slave_count"] = int(capacity.get("used", result["slave_count"]))
                result["available_slots"] = int(capacity.get("available", result["available_slots"]))
        active_target = getattr(runtime, "active_pairing_target", None)
        if callable(active_target):
            result["active_pairing_target"] = dict(active_target() or {})
        nearby_getter = getattr(manager, "nearby_nodes", None)
        if callable(nearby_getter):
            nearby = []
            for node in nearby_getter():
                nearby.append({
                    "node_id": str(node.node_id), "name": str(node.name or node.node_id),
                    "role": str(node.role), "addresses": [str(value) for value in node.addresses],
                    "port": int(node.port), "content_port": int(node.content_port),
                    "window_id": str(node.window_id), "pairing_open": bool(node.pairing_open),
                    "created_at": int(node.created_at or 0),
                })
            result["nearby_nodes"] = nearby
        registry = getattr(runtime, "registry", None)
        if registry is not None:
            result["nodes"] = [
                {"node_id": str(node.node_id), "name": str(node.name), "online": bool(node.online)}
                for node in registry.nodes
            ]
            result["slave_count"] = len(registry.nodes)
            result["available_slots"] = max(0, result["max_slaves"] - result["slave_count"])
        store = getattr(runtime, "store", None)
        if store is not None:
            try:
                result["slave_paired"] = bool(store.exists("slave"))
            except Exception:
                result["slave_paired"] = False
        return result

    def cluster_start_pairing(self, node_id: str | None = None, window_id: str | None = None) -> dict[str, Any]:
        manager = getattr(state, "_cluster_runtime", None)
        runtime = getattr(manager, "runtime", None) if manager is not None else None
        if runtime is None:
            raise RuntimeError("cluster_runtime_unavailable")
        # Starting the same ceremony twice can happen with a physical double-click
        # or a delayed WebView event. Treat an already-active local ceremony as
        # idempotent instead of turning a harmless duplicate click into an API
        # failure that tears down the desktop shell.
        ceremony = getattr(runtime, "ceremony", None)
        if ceremony is not None and not bool(getattr(ceremony, "closed", False)):
            return self.cluster_snapshot()
        effective_role = state.effective_cluster_role()
        if effective_role == "master":
            if not node_id or not window_id:
                raise ValueError("cluster_target_required")
            runtime.begin_pairing(str(node_id), str(window_id))
        elif effective_role == "slave":
            runtime.start_pairing()
        else:
            raise ValueError("cluster_role_standalone")
        return self.cluster_snapshot()

    def cluster_confirm_pairing(self, matches: bool) -> dict[str, Any]:
        manager = getattr(state, "_cluster_runtime", None)
        runtime = getattr(manager, "runtime", None) if manager is not None else None
        if runtime is None:
            raise RuntimeError("cluster_runtime_unavailable")
        runtime.confirm_pairing(bool(matches))
        return self.cluster_snapshot()

    def cluster_unlink_node(self, node_id: str) -> dict[str, Any]:
        manager = getattr(state, "_cluster_runtime", None)
        runtime = getattr(manager, "runtime", None) if manager is not None else None
        if runtime is None or not hasattr(runtime, "remove_node"):
            raise RuntimeError("cluster_master_runtime_unavailable")
        runtime.remove_node(str(node_id))
        return self.cluster_snapshot()

    def cluster_unpair_local(self) -> dict[str, Any]:
        manager = getattr(state, "_cluster_runtime", None)
        runtime = getattr(manager, "runtime", None) if manager is not None else None
        if runtime is not None and hasattr(runtime, "unpair_local"):
            runtime.unpair_local()
            return self.cluster_snapshot()

        # Local Slave cleanup is intentionally available with the server
        # stopped.  It only removes this machine's joined identity and trust
        # material; it does not pretend to revoke anything on an offline Master.
        # Round7 compatibility marker: state.CLUSTER_ROLE != "slave"
        if state.CLUSTER_ROLE not in ("slave", "auto"):
            raise RuntimeError("cluster_slave_runtime_unavailable")
        from src.core.cluster.identity import ClusterIdentityStore, joined_slave_files_exist
        from src.core.cluster.key_store import default_backend
        if joined_slave_files_exist(state._CONFIG_DIR):
            ClusterIdentityStore(state._CONFIG_DIR, default_backend(state._CONFIG_DIR)).delete_joined_identity()
        return self.cluster_snapshot()

    def security_snapshot(self) -> dict[str, Any]:
        self._require_vault_ready()
        from src.runtime.security_monitor_runtime import security_monitor_runtime
        return security_monitor_runtime.snapshot()

    def update_security_monitor(self, values: dict[str, Any]) -> dict[str, Any]:
        self._require_vault_ready()
        from src.runtime.security_monitor_runtime import security_monitor_runtime
        return security_monitor_runtime.configure(values)

    def clear_security_history(self) -> dict[str, Any]:
        self._require_vault_ready()
        from src.runtime.security_monitor_runtime import security_monitor_runtime
        return security_monitor_runtime.clear_history()

    def unblock_security_ip(self, ip: str) -> dict[str, Any]:
        self._require_vault_ready()
        from src.runtime.security_monitor_runtime import security_monitor_runtime
        return security_monitor_runtime.unblock(ip)

    def history_snapshot(self) -> dict[str, Any]:
        self._require_vault_ready()
        return {
            "items": [
                {
                    "path": str(item.get("path", "")),
                    "name": Path(str(item.get("path", ""))).name or str(item.get("path", "")),
                    "share_count": int(item.get("share_count", 0)),
                    "last_shared_at": float(item.get("last_shared_at", 0.0)),
                }
                for item in state.FOLDER_SHARE_HISTORY
            ]
        }

    def updates_snapshot(self) -> dict[str, Any]:
        return update_runtime_controller.base_snapshot()

    def check_updates(self) -> dict[str, Any]:
        return update_runtime_controller.check()

    def about_snapshot(self) -> dict[str, Any]:
        from src.core.local_data_reset import status as local_data_reset_status
        return {
            "version": str(VERSION),
            "company": "MÉLO TECHNOLOGY",
            "privacy_url": "https://www.netshareplayer.com/privacy-policy",
            "terms_url": "https://www.netshareplayer.com/",
            "maintenance": local_data_reset_status().as_dict(),
        }

    def clear_cache_and_data(self) -> dict[str, Any]:
        from src.core.local_data_reset import clear_cache_and_data
        return clear_cache_and_data()
