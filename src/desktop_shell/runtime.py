"""Native PyWebView runtime for the NetShare desktop shell.

The startup path deliberately uses a dedicated frameless splash window instead
of rendering a splash inside the main application window.  This mirrors the
legacy Tkinter banner: no native close/minimize chrome is exposed while startup
work is settling, and the real application stays hidden until it is ready.
"""

from __future__ import annotations

from threading import Event, Lock
import sys
import time
from typing import Any

from src.desktop_api import DesktopApi
from src.ui_event_bus import ACTIVITY_APPENDED, EventPublisher, UiEventBus
from src.runtime.activity_runtime import activity_runtime

from .assets import app_icon, shell_entrypoint, splash_entrypoint, tray_icon
from .bridge import ShellBridge
from .event_forwarder import WebViewEventForwarder
from .observability import build_shell_logger, safe_log
from .placement import center_window_on_primary_screen
from .webview_adapter import load_webview
from .tray import SystemTrayController


class DesktopShellRuntime:
    """Compose PyWebView with the already-established backend boundaries."""

    def __init__(
        self,
        *,
        desktop_api: DesktopApi | None = None,
        event_bus: UiEventBus | None = None,
        webview_module: Any | None = None,
        logger: Any | None = None,
        debug: bool = False,
        minimum_splash_seconds: float = 3.0,
        frontend_ready_timeout_seconds: float = 30.0,
    ) -> None:
        self._log = logger or build_shell_logger("DesktopShellRuntime")
        self._desktop_api = desktop_api or DesktopApi()
        self._owns_bus = event_bus is None
        self._bus = event_bus or UiEventBus(auto_start=False)
        self._publisher = EventPublisher(self._bus)
        self._frontend_ready = Event()
        self._bridge = ShellBridge(
            self._desktop_api,
            self._publisher,
            frontend_ready_callback=self._mark_frontend_ready,
        )
        self._forwarder = WebViewEventForwarder(self._bus)
        self._webview = webview_module
        self._debug = bool(debug)
        self._window: Any | None = None
        self._splash_window: Any | None = None
        self._minimum_splash_seconds = max(0.0, float(minimum_splash_seconds))
        self._frontend_ready_timeout_seconds = max(
            self._minimum_splash_seconds,
            float(frontend_ready_timeout_seconds),
        )
        self._splash_started_at = 0.0
        self._activity_runtime = activity_runtime
        self._activity_subscription = self._activity_runtime.subscribe(self._on_activity_runtime_event)
        self._closed = False
        self._close_lock = Lock()
        self._allow_window_close = False
        self._tray: SystemTrayController | None = None

    @property
    def bridge(self) -> ShellBridge:
        return self._bridge

    @property
    def event_bus(self) -> UiEventBus:
        return self._bus

    @property
    def window(self) -> Any | None:
        return self._window

    @property
    def splash_window(self) -> Any | None:
        return self._splash_window

    def run(self) -> None:
        """Create the frameless splash + hidden main window, then enter the GUI loop."""
        webview = self._webview or load_webview()
        self._webview = webview
        entrypoint = shell_entrypoint()
        splash = splash_entrypoint()
        self._bus.start()
        self._forwarder.start()

        try:
            # First window: legacy-style startup banner.  It is intentionally
            # frameless/non-resizable so there is no native close button.
            self._splash_window = webview.create_window(
                "NetShare Server",
                url=str(splash),
                width=640,
                height=300,
                min_size=(640, 300),
                resizable=False,
                frameless=True,
                easy_drag=True,
                on_top=True,
                hidden=True,
                background_color="#000000",
                text_select=False,
            )

            # Second window: the actual application loads in the background but
            # stays hidden until JS reports ready and the 3-second minimum banner
            # duration has elapsed.
            self._window = webview.create_window(
                "NetShare Server",
                url=str(entrypoint),
                js_api=self._bridge,
                width=1180,
                height=760,
                min_size=(420, 520),
                resizable=True,
                hidden=True,
                background_color="#000000",
                text_select=True,
            )
            self._forwarder.attach_window(self._window)
            self._bridge.attach_window(self._window, webview)
            self._bind_lifecycle_events(self._window)
            self._tray = SystemTrayController(
                icon_path=tray_icon(),
                on_open=self._show_from_tray,
                on_quit=self._quit_from_tray,
                logger=self._log,
                language_provider=self._tray_language,
            )
            tray_started = self._tray.start()
            safe_log(
                self._log,
                "shell.tray.started" if tray_started else "shell.tray.unavailable",
                operation="start_tray",
                status="success" if tray_started else "unavailable",
                error_code=None if tray_started else self._tray.last_error,
            )
            safe_log(
                self._log,
                "shell.window.created",
                operation="create_window",
                status="success",
                asset_mode="local_http",
                splash_mode="frameless",
                minimum_splash_seconds=self._minimum_splash_seconds,
            )

            icon_path = app_icon()
            # PyWebView runs the startup callback on a worker after the GUI loop
            # is alive.  That lets the splash remain responsive while we wait.
            webview.start(
                self._startup_sequence,
                debug=self._debug,
                http_server=True,
                private_mode=True,
                icon=str(icon_path) if icon_path is not None else None,
            )
        except Exception as exc:
            safe_log(
                self._log,
                "shell.runtime.failed",
                operation="run",
                status="failed",
                level="error",
                error_type=type(exc).__name__,
            )
            raise
        finally:
            self.close()

    def close(self) -> None:
        """Idempotently detach UI forwarding without touching business runtime."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            try:
                if self._tray is not None:
                    self._tray.stop()
            except Exception:
                pass
            # The shell may be closed while the HTTP runtime is still tearing
            # down. Always release process power assertions on desktop exit;
            # the persisted Keep Alive preference remains unchanged.
            try:
                from src.runtime.permissions_runtime import permissions_runtime_controller
                permissions_runtime_controller.release_runtime_inhibitor()
            except Exception:
                pass
            try:
                self._activity_runtime.unsubscribe(self._activity_subscription)
            except Exception:
                pass
            self._forwarder.close()
        finally:
            if self._owns_bus:
                try:
                    self._bus.close(drain=True)
                except Exception:
                    pass
        safe_log(
            self._log,
            "shell.window.closed",
            operation="close",
            status="success",
        )

    def _mark_frontend_ready(self) -> None:
        self._frontend_ready.set()

    def _startup_sequence(self) -> None:
        """Center/show the banner, then keep it up until startup is ready.

        ``webview.start`` invokes this callback only after the native GUI loop
        exists, which makes ``webview.screens`` and ``Window.move`` reliable on
        Windows, macOS and Linux.
        """
        placement = center_window_on_primary_screen(
            self._splash_window,
            self._webview,
            width=640,
            height=300,
        ) if self._splash_window is not None and self._webview is not None else None
        self._safe_window_call(self._splash_window, "show")
        self._safe_window_call(self._splash_window, "restore")
        safe_log(
            self._log,
            "shell.splash.shown",
            operation="show_splash",
            status="success",
            centered=bool(placement),
            **(placement or {}),
        )
        self._release_splash_when_ready()

    def _release_splash_when_ready(self) -> None:
        """Keep the visible banner up for >=3s and until the frontend is ready."""
        # The timer starts after the centered splash has actually been shown.
        self._splash_started_at = time.monotonic()
        ready = self._frontend_ready.wait(timeout=self._frontend_ready_timeout_seconds)
        elapsed = max(0.0, time.monotonic() - self._splash_started_at)
        remaining = max(0.0, self._minimum_splash_seconds - elapsed)
        if remaining:
            time.sleep(remaining)

        # Show the application first, then dismiss the always-on-top splash so
        # there is no visible desktop flash between windows.
        self._safe_window_call(self._window, "show")
        self._safe_window_call(self._window, "restore")
        self._safe_window_call(self._splash_window, "destroy")
        safe_log(
            self._log,
            "shell.splash.released",
            operation="release_splash",
            status="success" if ready else "timeout",
            frontend_ready=bool(ready),
            minimum_splash_seconds=self._minimum_splash_seconds,
            duration_ms=round(max(0.0, time.monotonic() - self._splash_started_at) * 1000.0, 3),
        )

    @staticmethod
    def _safe_window_call(window: Any | None, method: str) -> bool:
        if window is None:
            return False
        callback = getattr(window, method, None)
        if not callable(callback):
            return False
        try:
            callback()
            return True
        except Exception:
            return False

    def _on_activity_runtime_event(self, activity: dict[str, Any]) -> None:
        try:
            self._publisher.publish(ACTIVITY_APPENDED, {"activity": dict(activity)})
        except Exception as exc:
            safe_log(
                self._log,
                "shell.activity.publish_failed",
                operation="activity_fanout",
                status="failed",
                level="warning",
                error_type=type(exc).__name__,
            )

    def _bind_lifecycle_events(self, window: Any) -> None:
        self._bind_event(window, "loaded", self._on_loaded)
        self._bind_event(window, "closing", self._on_closing)
        self._bind_event(window, "closed", self._on_closed)
        self._bind_event(window, "resized", self._lifecycle_logger("resized"))
        self._bind_event(window, "minimized", self._on_minimized)
        self._bind_event(window, "restored", self._lifecycle_logger("restored"))

    @staticmethod
    def _bind_event(window: Any, name: str, callback: Any) -> bool:
        events = getattr(window, "events", None)
        event = getattr(events, name, None) if events is not None else None
        if event is None:
            return False
        try:
            event += callback
            return True
        except Exception:
            return False

    def _on_loaded(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        self._forwarder.mark_ready()
        safe_log(
            self._log,
            "shell.window.loaded",
            operation="loaded",
            status="success",
        )


    def _tray_language(self) -> str:
        """Resolve persisted UI language through the DesktopApi boundary."""
        try:
            response = self._desktop_api.get_settings_snapshot()
            if response.get("ok") and isinstance(response.get("data"), dict):
                return str(response["data"].get("language") or "en")
        except Exception:
            pass
        return "en"

    def _on_closing(self, *args: Any, **kwargs: Any) -> bool:
        del args, kwargs
        if self._allow_window_close:
            return True
        if self._tray is not None and self._tray.running:
            self._safe_window_call(self._window, "hide")
            self._set_macos_dock_visible(False)
            safe_log(
                self._log,
                "shell.window.hidden_to_tray",
                operation="close_to_tray",
                status="success",
            )
            # PyWebView cancels the native close when a closing handler returns False.
            return False
        # Never leave an invisible/unrecoverable process when the tray backend
        # is unavailable (headless/minimal Linux, missing dependency, etc.).
        return True

    def _on_minimized(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        if self._tray is not None and self._tray.running:
            self._safe_window_call(self._window, "hide")
            self._set_macos_dock_visible(False)
        safe_log(
            self._log,
            "shell.window.minimized",
            operation="minimized",
            status="success",
            hidden_to_tray=bool(self._tray is not None and self._tray.running),
        )

    def _show_from_tray(self) -> None:
        self._set_macos_dock_visible(True)
        self._safe_window_call(self._window, "show")
        self._safe_window_call(self._window, "restore")
        self._activate_macos_application()
        safe_log(
            self._log,
            "shell.window.restored_from_tray",
            operation="restore_from_tray",
            status="success",
        )

    @staticmethod
    def _set_macos_dock_visible(visible: bool) -> None:
        """Toggle Dock presence while the app is operating as a menu-bar app.

        Hiding a Cocoa window alone leaves the application icon in the Dock.
        Accessory activation policy is the native equivalent of close-to-tray;
        restoring NetShare switches back to the regular app policy first.
        """
        if sys.platform != "darwin":
            return
        try:
            from AppKit import (
                NSApplication,
                NSApplicationActivationPolicyAccessory,
                NSApplicationActivationPolicyRegular,
            )
            application = NSApplication.sharedApplication()
            policy = (
                NSApplicationActivationPolicyRegular
                if visible
                else NSApplicationActivationPolicyAccessory
            )
            application.setActivationPolicy_(policy)
        except Exception:
            # Tray recovery must never make window lifecycle fatal.
            pass

    @staticmethod
    def _activate_macos_application() -> None:
        if sys.platform != "darwin":
            return
        try:
            from AppKit import NSApplication
            NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        except Exception:
            pass

    def _quit_from_tray(self) -> None:
        self._allow_window_close = True
        try:
            if self._tray is not None:
                self._tray.stop()
        finally:
            if not self._safe_window_call(self._window, "destroy"):
                self.close()

    def _on_closed(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        self.close()

    def _lifecycle_logger(self, name: str):
        def callback(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            safe_log(
                self._log,
                f"shell.window.{name}",
                operation=name,
                status="success",
            )

        return callback


def run_desktop_shell(*, debug: bool = False) -> None:
    DesktopShellRuntime(debug=debug).run()
