"""Compatibility adapter over ``src.state`` without changing its schema."""

from __future__ import annotations

import threading
from typing import Any


class StateAdapter:
    def __init__(self, state_module=None):
        if state_module is None:
            import src.state as state_module
        self.state = state_module
        self._lock = threading.RLock()

    def shared_roots(self):
        return tuple(self.state.SHARED_ROOTS)

    def feature_flags(self) -> dict[str, bool]:
        return dict(self.state.FEATURE_FLAGS)

    def settings_values(self) -> dict[str, Any]:
        s = self.state
        return {
            "theme": s.THEME,
            "language": s.LANGUAGE,
            "text_size": s.TEXT_SIZE,
            "show_advanced_settings": s.SHOW_ADVANCED_SETTINGS,
            "ffmpeg_path": s.FFMPEG_PATH,
            "performance_preset": s.PERFORMANCE_PRESET,
            "index_workers": s.INDEX_WORKERS,
            "analysis_workers": s.ANALYSIS_WORKERS,
            "gpu_encoder_preference": s.GPU_ENCODER_PREFERENCE,
            "log_buffer_lines": s.LOG_BUFFER_LINES,
            "cluster_role": s.CLUSTER_ROLE,
            "password_reminder_days": s.PASSWORD_REMINDER_DAYS,
            "local_password_configured": bool(s.SAVED_LOCAL_PASSWORD),
        }

    def public_values(self) -> dict[str, Any]:
        s = self.state
        return {
            "community_key_configured": bool(s.COMMUNITY_PASSWORD_CREDENTIAL or s.COMMUNITY_PASSWORD),
            "admin_key_configured": bool(s.ADMIN_PASSWORD_CREDENTIAL or s.ADMIN_PASSWORD),
            "community_browse_root": bool(s.COMMUNITY_BROWSE_ROOT),
            "community_download": bool(s.COMMUNITY_DOWNLOAD),
            "community_upload": bool(s.COMMUNITY_UPLOAD),
            "public_upload_mode": str(s.PUBLIC_UPLOAD_MODE),
            "max_uploads_per_hour": int(s.MAX_UPLOADS_PER_HOUR),
            "max_upload_size_mb": int(s.MAX_UPLOAD_SIZE_MB),
            "allowed_upload_extensions": [str(value) for value in sorted(s.ALLOWED_UPLOAD_EXTENSIONS)],
            "web_access_enabled": bool(s.WEB_ACCESS_ENABLED),
            "web_password_configured": bool(s.WEB_PASSWORD_CREDENTIAL),
        }

    def trusted_devices(self) -> dict[str, object]:
        return dict(self.state.TRUSTED_DEVICES)

    def pending_uploads(self) -> tuple[dict[str, Any], ...]:
        with self.state.UPLOAD_REQUEST_LOCK:
            return tuple(dict(item) for item in self.state.PENDING_UPLOAD_REQUESTS.values())

    def update_public_config(self, **values: Any) -> None:
        allowed = {
            "COMMUNITY_PASSWORD", "ADMIN_PASSWORD", "COMMUNITY_BROWSE_ROOT",
            "COMMUNITY_DOWNLOAD", "COMMUNITY_UPLOAD", "PUBLIC_UPLOAD_MODE",
            "MAX_UPLOADS_PER_HOUR", "MAX_UPLOAD_SIZE_MB", "ALLOWED_UPLOAD_EXTENSIONS",
        }
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unsupported public setting(s): {sorted(unknown)}")
        with self._lock:
            for key, value in values.items():
                setattr(self.state, key, value)
            self.state.save_public_config()

    def resolve_upload(self, request_id: str, accepted: bool):
        return self.state.resolve_public_upload_request(request_id, accepted)

    def revoke_device(self, device_id: str) -> None:
        self.state.revoke_device(device_id)

    def save_appearance(self, **values: Any) -> None:
        self.state.save_appearance(**values)

    def save_language(self, language: str) -> None:
        self.state.save_language(language)

    def save_show_advanced_settings(self, enabled: bool) -> None:
        self.state.save_show_advanced_settings(enabled)

    def local_password_secret(self) -> str:
        # This value is exposed only through the local PyWebView bridge for the
        # explicit password-management dialog. It is never part of HTTP state.
        return str(self.state.SAVED_LOCAL_PASSWORD or "")

    def save_local_password(self, password: str) -> None:
        self.state.save_local_password(password)

    def clear_local_password_auth_failures(self) -> int:
        callback = getattr(self.state, "clear_auth_failures_by_prefix", None)
        if not callable(callback):
            # Compatibility for embedders/test doubles predating the bounded
            # auth-failure registry. Password rotation must still succeed.
            return 0
        return int(callback("password:local:"))

    def save_password_reminder_days(self, days: int) -> None:
        self.state.save_password_reminder_days(days)

    def save_ffmpeg_path(self, path: str) -> None:
        self.state.save_ffmpeg_path(path)

    def save_performance_preset(self, preset: str) -> None:
        self.state.save_performance_preset(preset)

    def save_worker_budget(self, index_workers: object, analysis_workers: object, *, changed: str):
        return self.state.save_worker_budget(index_workers, analysis_workers, changed=changed)

    def save_gpu_encoder_preference(self, preference: str, capabilities=None) -> None:
        self.state.save_gpu_encoder_preference(preference, capabilities=capabilities)

    def save_log_buffer_lines(self, value: object) -> int:
        return self.state.save_log_buffer_lines(value)

    def save_cluster_role(self, role: str) -> None:
        self.state.save_cluster_role(role)

    def set_hidden_path(self, slot: str, relative_path: str, hidden: bool) -> bool:
        return self.state.set_hidden_path(slot, relative_path, hidden)

    def set_shared_roots(self, paths, *, persist: bool = True):
        return self.state.set_shared_roots(paths, persist=persist)

    def clear_folder_share_history(self) -> None:
        self.state.clear_folder_share_history()

    def set_web_password(self, password: str, *, enabled: bool = True) -> None:
        self.state.set_web_password(password, enabled=enabled)

    def disable_web_access(self) -> None:
        self.state.disable_web_access()
