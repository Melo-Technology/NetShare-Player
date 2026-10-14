"""Cross-platform native window placement helpers for the desktop shell.

PyWebView reports screen geometry and window coordinates in logical pixels on
Windows, macOS and Linux.  Keeping placement in this tiny adapter avoids
platform-specific GUI dependencies in the application entrypoint.
"""

from __future__ import annotations

from typing import Any


def _screen_is_primary(screen: Any) -> bool:
    """Best-effort primary-screen detection across PyWebView backend versions."""
    for name in ("is_primary", "primary"):
        value = getattr(screen, name, None)
        if isinstance(value, bool):
            return value
    return False


def _available_screens(webview_module: Any) -> list[Any]:
    try:
        screens = getattr(webview_module, "screens", None)
        if screens is None:
            return []
        return list(screens)
    except Exception:
        return []


def primary_screen(webview_module: Any) -> Any | None:
    """Return the primary screen, falling back to PyWebView's first screen."""
    screens = _available_screens(webview_module)
    if not screens:
        return None
    return next((screen for screen in screens if _screen_is_primary(screen)), screens[0])


def center_window_on_primary_screen(
    window: Any,
    webview_module: Any,
    *,
    width: int | None = None,
    height: int | None = None,
) -> dict[str, int] | None:
    """Center ``window`` on the primary display using logical pixel geometry.

    The helper intentionally runs after the PyWebView GUI loop has started so
    screen information and ``Window.move`` are available on WebView2, WKWebView,
    WebKitGTK and Qt backends.  If screen information is unavailable, ``None``
    is returned and the caller can rely on PyWebView's native default centering.
    """
    screen = primary_screen(webview_module)
    if screen is None:
        return None

    try:
        screen_x = int(getattr(screen, "x"))
        screen_y = int(getattr(screen, "y"))
        screen_width = int(getattr(screen, "width"))
        screen_height = int(getattr(screen, "height"))
        window_width = int(width if width is not None else getattr(window, "width"))
        window_height = int(height if height is not None else getattr(window, "height"))
    except (TypeError, ValueError, AttributeError):
        return None

    # Keep the full banner inside the chosen screen even on very small virtual
    # displays. Negative screen origins (multi-monitor layouts) are preserved.
    x = screen_x + max(0, (screen_width - window_width) // 2)
    y = screen_y + max(0, (screen_height - window_height) // 2)

    mover = getattr(window, "move", None)
    if not callable(mover):
        return None
    try:
        mover(x, y)
    except Exception:
        return None
    return {"x": x, "y": y, "screen_width": screen_width, "screen_height": screen_height}
