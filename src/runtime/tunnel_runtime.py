"""Shared lifecycle for NetShare public tunnel processes.

This module extracts only process/runtime ownership that previously lived in
``ServerLifecycleMixin``. Tkinter keeps prompts/widgets/translations while both
Tkinter and Application Services delegate tunnel process ownership here.
"""
from __future__ import annotations

from collections.abc import Callable
import threading
from typing import Any

import src.state as state
from src.core.tunnel import PublicTunnel

Callback = Callable[..., None]


class TunnelRuntimeError(RuntimeError):
    """Raised when a requested tunnel runtime cannot be started safely."""


class TunnelRuntimeController:
    def __init__(self, *, public_tunnel_factory=None, cloudflare_module=None) -> None:
        self._lock = threading.RLock()
        self._public_tunnel_factory = public_tunnel_factory or PublicTunnel
        self._cloudflare_module = cloudflare_module
        self._ssh_tunnel = None
        self._ssh_active = False
        self._ssh_url = ""
        self._cf_tunnel = None
        self._cf_active = False
        self._cf_url = ""
        self._cf_hostname = ""

    def _cf(self):
        if self._cloudflare_module is not None:
            return self._cloudflare_module
        from src.core import cloudflare_tunnel
        return cloudflare_tunnel

    @staticmethod
    def _safe_callback(callback: Callback | None, *args: Any) -> None:
        if callback is None:
            return
        try:
            callback(*args)
        except Exception:
            pass

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "ssh": {
                    "active": bool(self._ssh_active),
                    "url": str(self._ssh_url or ""),
                },
                "cloudflare": {
                    "active": bool(self._cf_active),
                    "url": str(self._cf_url or ""),
                    "hostname": str(self._cf_hostname or ""),
                },
                "any_active": bool(self._ssh_active or self._cf_active),
            }

    def ssh_handle(self):
        with self._lock:
            return self._ssh_tunnel

    def cloudflare_handle(self):
        with self._lock:
            return self._cf_tunnel

    def start_ssh(
        self,
        *,
        public_port: int,
        admin_password: str,
        on_url: Callback | None = None,
        on_error: Callback | None = None,
        on_stop: Callback | None = None,
        on_reconnecting: Callback | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if self._ssh_active:
                return self.snapshot()
            tunnel = self._public_tunnel_factory(port=int(public_port))
            self._ssh_tunnel = tunnel
            self._ssh_active = True
            self._ssh_url = ""
            state.TUNNEL_PASSWORD = str(admin_password or "")
            state.TUNNEL_ACTIVE = True

        def url_callback(url: str):
            with self._lock:
                self._ssh_url = str(url or "")
            self._safe_callback(on_url, str(url or ""))

        def error_callback(message: str):
            # Mirrors the legacy callback: GUI active state changes but
            # state.TUNNEL_ACTIVE is not rewritten here.
            with self._lock:
                self._ssh_active = False
            self._safe_callback(on_error, message)

        try:
            tunnel.start(
                on_url=url_callback,
                on_error=error_callback,
                on_stop=lambda: self._safe_callback(on_stop),
                on_reconnecting=lambda delay, attempt: self._safe_callback(on_reconnecting, delay, attempt),
            )
        except Exception as exc:
            with self._lock:
                self._ssh_tunnel = None
                self._ssh_active = False
                self._ssh_url = ""
                state.TUNNEL_PASSWORD = ""
                if not self._cf_active:
                    state.TUNNEL_ACTIVE = False
            raise TunnelRuntimeError(str(exc)) from exc
        return self.snapshot()

    def stop_ssh(self) -> dict[str, Any]:
        with self._lock:
            tunnel = self._ssh_tunnel
            self._ssh_tunnel = None
            self._ssh_active = False
            self._ssh_url = ""
            state.TUNNEL_PASSWORD = ""
            if not self._cf_active:
                state.TUNNEL_ACTIVE = False
        if tunnel is not None:
            try:
                tunnel.stop()
            except Exception:
                pass
        return self.snapshot()

    def cloudflare_setup_status(self, hostname: str) -> dict[str, Any]:
        cf = self._cf()
        hostname = str(hostname or "").strip()
        if hostname:
            status = cf.setup_status(hostname)
        else:
            status = {
                "installed": bool(cf.is_installed()),
                "logged_in": bool(cf.is_logged_in()) if hasattr(cf, "is_logged_in") else False,
                "tunnel_created": False,
                "tunnel_id": None,
                "config_written": False,
            }
        return {
            "installed": bool(status.get("installed")),
            "logged_in": bool(status.get("logged_in")),
            "tunnel_created": bool(status.get("tunnel_created")),
            "tunnel_id": str(status.get("tunnel_id")) if status.get("tunnel_id") else None,
            "config_written": bool(status.get("config_written")),
        }

    def cloudflare_login(self) -> dict[str, Any]:
        result = dict(self._cf().login())
        return {
            "ok": bool(result.get("ok")),
            "error": str(result.get("error")) if result.get("error") else None,
        }

    def cloudflare_setup(self, *, hostname: str, public_port: int) -> dict[str, Any]:
        hostname = str(hostname or "").strip()
        if not hostname:
            raise ValueError("hostname is required")
        cf = self._cf()
        created = dict(cf.create_tunnel())
        if not created.get("ok"):
            return {"ok": False, "error": str(created.get("error") or "create_failed")}
        routed = dict(cf.route_dns(hostname))
        if not routed.get("ok"):
            return {"ok": False, "error": str(routed.get("error") or "route_failed")}
        config_path = cf.write_config(created["tunnel_id"], hostname, int(public_port))
        return {"ok": True, "hostname": hostname, "config_path": str(config_path)}

    def start_cloudflare(
        self,
        *,
        hostname: str,
        public_port: int,
        admin_password: str,
        on_url: Callback | None = None,
        on_error: Callback | None = None,
        on_stop: Callback | None = None,
        on_reconnecting: Callback | None = None,
    ) -> dict[str, Any]:
        hostname = str(hostname or "").strip()
        if not hostname:
            raise ValueError("hostname is required")
        cf = self._cf()
        if not cf.is_installed():
            raise TunnelRuntimeError("cloudflared_not_installed")
        status = cf.setup_status(hostname)
        if not status.get("tunnel_created") or not status.get("config_written"):
            raise TunnelRuntimeError("cloudflare_setup_incomplete")
        config_path = cf._APP_TUNNEL_DIR / "config.yml"
        cf.retarget_config(config_path, int(public_port))

        with self._lock:
            if self._cf_active:
                return self.snapshot()
            tunnel = cf.CloudflareTunnel(config_path, hostname)
            self._cf_tunnel = tunnel
            self._cf_active = True
            self._cf_url = ""
            self._cf_hostname = hostname
            state.TUNNEL_PASSWORD = str(admin_password or "")
            state.TUNNEL_ACTIVE = True

        def url_callback(url: str):
            with self._lock:
                self._cf_url = str(url or "")
            self._safe_callback(on_url, str(url or ""))

        def error_callback(message: str):
            with self._lock:
                self._cf_active = False
            self._safe_callback(on_error, message)

        try:
            tunnel.start(
                on_url=url_callback,
                on_error=error_callback,
                on_stop=lambda: self._safe_callback(on_stop),
                on_reconnecting=lambda delay, attempt: self._safe_callback(on_reconnecting, delay, attempt),
            )
        except Exception as exc:
            with self._lock:
                self._cf_tunnel = None
                self._cf_active = False
                self._cf_url = ""
                if not self._ssh_active:
                    state.TUNNEL_ACTIVE = False
            raise TunnelRuntimeError(str(exc)) from exc
        return self.snapshot()

    def stop_cloudflare(self) -> dict[str, Any]:
        with self._lock:
            tunnel = self._cf_tunnel
            self._cf_tunnel = None
            self._cf_active = False
            self._cf_url = ""
            if not self._ssh_active:
                state.TUNNEL_ACTIVE = False
            # Intentionally preserve TUNNEL_PASSWORD: legacy Cloudflare stop
            # did not clear it. SSH stop still clears it exactly as before.
        if tunnel is not None:
            try:
                tunnel.stop()
            except Exception:
                pass
        return self.snapshot()

    def stop_all(self) -> dict[str, Any]:
        self.stop_ssh()
        self.stop_cloudflare()
        return self.snapshot()


tunnel_runtime_controller = TunnelRuntimeController()

__all__ = ["TunnelRuntimeController", "TunnelRuntimeError", "tunnel_runtime_controller"]
