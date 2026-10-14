"""Cross-platform system tray / menu-bar integration for the desktop shell.

Windows exposes the notification area, macOS exposes a menu-bar status item,
and Linux uses whichever pystray backend is available (preferably
AppIndicator/GTK). The controller is deliberately fail-open for window
lifecycle: if the tray cannot start, NetShare keeps ordinary close/minimize
semantics instead of trapping the user in an invisible process.

C5.3.1 deliberately uses the backend startup model documented by pystray:
* macOS uses ``run_detached`` *with the same NSApplication* that owns the
  PyWebView/Cocoa main loop;
* Windows runs the Win32 tray loop in its own thread (explicitly supported by
  pystray and independent from the WinForms/WebView loop);
* Linux keeps ``run_detached`` so GTK/AppIndicator can share the GObject loop.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
from threading import Event, RLock, Thread, current_thread
from typing import Any, Callable

from src import i18n


class SystemTrayController:
    """Own a pystray icon without importing desktop-only dependencies eagerly."""

    def __init__(
        self,
        *,
        icon_path: Path | None,
        on_open: Callable[[], None],
        on_quit: Callable[[], None],
        logger: Any | None = None,
        language_provider: Callable[[], str] | None = None,
        pystray_module: Any | None = None,
        image_module: Any | None = None,
        platform_provider: Callable[[], str] | None = None,
        mac_application_provider: Callable[[], Any] | None = None,
        startup_timeout_seconds: float = 3.0,
    ) -> None:
        self._icon_path = Path(icon_path) if icon_path is not None else None
        self._on_open = on_open
        self._on_quit = on_quit
        self._logger = logger
        self._language_provider = language_provider or (lambda: i18n.DEFAULT_LANGUAGE)
        self._pystray = pystray_module
        self._image_module = image_module
        self._platform_provider = platform_provider or (lambda: sys.platform)
        self._mac_application_provider = mac_application_provider
        self._startup_timeout_seconds = max(0.5, float(startup_timeout_seconds))
        self._icon: Any | None = None
        self._thread: Thread | None = None
        self._running = False
        self._lock = RLock()
        self._last_error: str | None = None

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._running)

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    def start(self) -> bool:
        """Prepare/start the tray and return False on any backend failure."""
        with self._lock:
            if self._running:
                return True
        try:
            pystray = self._pystray or importlib.import_module("pystray")
            if not bool(getattr(pystray.Icon, "HAS_MENU", True)):
                self._set_failure("tray_menu_unavailable")
                return False

            image_module = self._image_module or importlib.import_module("PIL.Image")
            image = self._load_image(image_module)
            if image is None:
                self._set_failure("tray_icon_missing")
                return False

            default_supported = bool(getattr(pystray.Icon, "HAS_DEFAULT_ACTION", False))
            menu = pystray.Menu(
                pystray.MenuItem(
                    lambda _item: self._text("tray_open"),
                    self._handle_open,
                    default=default_supported,
                ),
                pystray.MenuItem(lambda _item: self._text("tray_quit"), self._handle_quit),
            )

            platform_name = str(self._platform_provider() or "").lower()
            icon_kwargs: dict[str, Any] = {}
            if platform_name == "darwin":
                # pystray documents that run_detached on macOS must receive the
                # NSApplication instance of the framework driving the Cocoa loop.
                # PyWebView also uses NSApplication.sharedApplication(), so both
                # components now share one native run loop instead of competing.
                icon_kwargs["darwin_nsapplication"] = self._mac_application()

            icon = pystray.Icon(
                "netshare-server",
                image,
                "NetShare Server",
                menu,
                **icon_kwargs,
            )

            if platform_name.startswith("win"):
                if not self._start_windows_loop(icon):
                    return False
            elif platform_name == "darwin":
                # macOS needs run_detached because Cocoa/PyWebView owns the main
                # run loop. Supply our own setup so the monochrome glyph is also
                # marked as an NSImage template: AppKit then tints it correctly
                # for both light and dark menu-bar appearances.
                icon.run_detached(setup=self._setup_macos_icon)
            else:
                # PyWebView GTK and pystray GTK/AppIndicator share the GObject
                # loop, so detached integration is appropriate on desktop Linux.
                icon.run_detached()

            with self._lock:
                self._pystray = pystray
                self._image_module = image_module
                self._icon = icon
                self._running = True
                self._last_error = None
            return True
        except ModuleNotFoundError as exc:
            self._set_failure(f"tray_dependency_missing:{getattr(exc, 'name', '') or 'unknown'}")
            return False
        except Exception as exc:
            self._set_failure(f"tray_start_failed:{type(exc).__name__}")
            return False


    @staticmethod
    def _setup_macos_icon(active_icon: Any) -> None:
        """Show the Darwin status item and opt into AppKit template tinting.

        pystray 0.19.5 converts the PIL bitmap to ``NSImage`` but does not mark
        monochrome images as templates. Without this, the supplied white glyph
        can disappear against a light macOS menu bar. The fallback is harmless:
        if backend internals change, the icon remains visible with its source
        colours instead of making tray startup fail.
        """
        active_icon.visible = True
        try:
            native_image = getattr(active_icon, "_icon_image", None)
            if native_image is not None and hasattr(native_image, "setTemplate_"):
                native_image.setTemplate_(True)
                status_item = getattr(active_icon, "_status_item", None)
                button = status_item.button() if status_item is not None else None
                if button is not None:
                    button.setImage_(native_image)
        except Exception:
            pass

    def _start_windows_loop(self, icon: Any) -> bool:
        """Run pystray's Win32 message loop independently from PyWebView."""
        ready = Event()
        failure: list[BaseException] = []

        def setup(active_icon: Any) -> None:
            try:
                active_icon.visible = True
            finally:
                ready.set()

        def worker() -> None:
            try:
                icon.run(setup=setup)
            except BaseException as exc:  # backend exceptions must not kill the app
                failure.append(exc)
                ready.set()

        thread = Thread(target=worker, name="NetShareSystemTray", daemon=True)
        thread.start()
        if not ready.wait(timeout=self._startup_timeout_seconds):
            try:
                icon.stop()
            except Exception:
                pass
            self._set_failure("tray_start_timeout")
            return False
        if failure:
            self._set_failure(f"tray_start_failed:{type(failure[0]).__name__}")
            return False
        self._thread = thread
        return True

    def _mac_application(self) -> Any:
        if self._mac_application_provider is not None:
            return self._mac_application_provider()
        appkit = importlib.import_module("AppKit")
        application = appkit.NSApplication.sharedApplication()
        if application is None:
            raise RuntimeError("macos_nsapplication_unavailable")
        return application

    def _load_image(self, image_module: Any) -> Any | None:
        candidates: list[Path] = []
        if self._icon_path is not None:
            candidates.append(self._icon_path)
        # Source fallback: binary patches/copies occasionally omit the root ICO.
        # Keeping a tiny PNG next to this module makes source runs deterministic,
        # while packaged builds still use the user's dedicated ICO when present.
        candidates.append(Path(__file__).resolve().parent / "resources" / "favicon-notification.png")
        for candidate in candidates:
            try:
                if candidate.is_file():
                    return image_module.open(str(candidate)).convert("RGBA")
            except Exception:
                continue
        return None

    def stop(self) -> None:
        with self._lock:
            icon = self._icon
            thread = self._thread
            self._icon = None
            self._thread = None
            self._running = False
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                pass
        if thread is not None and thread is not current_thread() and thread.is_alive():
            thread.join(timeout=1.0)

    def refresh_menu(self) -> None:
        with self._lock:
            icon = self._icon
        if icon is not None:
            try:
                icon.update_menu()
            except Exception:
                pass

    def _handle_open(self, _icon: Any = None, _item: Any = None) -> None:
        try:
            self._on_open()
        except Exception:
            pass

    def _handle_quit(self, _icon: Any = None, _item: Any = None) -> None:
        try:
            self._on_quit()
        except Exception:
            pass

    def _resolved_language(self) -> str:
        try:
            requested = str(self._language_provider() or i18n.DEFAULT_LANGUAGE).lower()
        except Exception:
            requested = i18n.DEFAULT_LANGUAGE
        if requested == i18n.SYSTEM_LANGUAGE:
            return i18n.system_language()
        return requested if requested in i18n.LANGUAGES else i18n.DEFAULT_LANGUAGE

    def _text(self, key: str) -> str:
        language = self._resolved_language()
        values = i18n._TRANSLATIONS.get(language, i18n._TRANSLATIONS[i18n.DEFAULT_LANGUAGE])
        return str(values.get(key) or i18n._TRANSLATIONS[i18n.DEFAULT_LANGUAGE].get(key) or key)

    def _set_failure(self, code: str) -> None:
        with self._lock:
            self._running = False
            self._icon = None
            self._last_error = str(code)
