"""Resolve local shell assets in source and frozen/bundled environments."""

from __future__ import annotations

from pathlib import Path
import sys

from .exceptions import DesktopShellAssetError


def application_root() -> Path:
    """Return the runtime root used for bundled frontend assets.

    PyInstaller-compatible builds expose extracted data under ``sys._MEIPASS``.
    Source runs resolve relative to this module instead of the process working
    directory so launching NetShare from another directory remains reliable.
    """
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(str(frozen_root)).resolve()
    return Path(__file__).resolve().parents[2]


def frontend_root() -> Path:
    root = application_root() / "frontend"
    if not root.is_dir():
        raise DesktopShellAssetError(f"frontend assets directory not found: {root}")
    return root


def shell_entrypoint() -> Path:
    entrypoint = frontend_root() / "index.html"
    if not entrypoint.is_file():
        raise DesktopShellAssetError(f"desktop shell entrypoint not found: {entrypoint}")
    return entrypoint


def splash_entrypoint() -> Path:
    """Return the dedicated frameless startup splash document."""
    entrypoint = frontend_root() / "splash.html"
    if not entrypoint.is_file():
        raise DesktopShellAssetError(f"desktop splash entrypoint not found: {entrypoint}")
    return entrypoint


def app_icon() -> Path | None:
    """Return the packaged/source application icon when available.

    Windows uses the existing ``favicon.ico``.  The function intentionally
    returns ``None`` instead of raising so a missing optional runtime icon can
    never prevent the desktop shell from starting.
    """
    icon = application_root() / "favicon.ico"
    return icon if icon.is_file() else None


def tray_icon() -> Path | None:
    """Return the dedicated monochrome system-tray/menu-bar icon when present.

    Frozen builds place the original ``favicon-notification.ico`` at the bundle
    root. Source trees also ship a tiny PNG copy beside the shell module as a
    defensive fallback, so a copied checkout cannot silently lose tray support
    merely because a binary root asset was omitted.
    """
    candidates = (
        application_root() / "favicon-notification.ico",
        Path(__file__).resolve().parent / "resources" / "favicon-notification.png",
    )
    return next((icon for icon in candidates if icon.is_file()), None)
