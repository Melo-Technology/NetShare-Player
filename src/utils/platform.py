"""Platform detection and single-instance protection for NetShare Server.

This module intentionally has no legacy desktop-toolkit dependency.  Duplicate-instance
notifications use native/optional OS facilities and fall back to stderr.
"""

from __future__ import annotations

import atexit
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from src.i18n import t


def _get_platform() -> str:
    p = sys.platform
    if p == "darwin":
        return "mac"
    if p.startswith("win"):
        return "windows"
    return "linux"


PLATFORM: str = _get_platform()

_win_mutex_handle = None
_linux_lock_sock = None
_LOCK_FILE = Path(tempfile.gettempdir()) / "netshare_player_v1.lock"


def _apple_script_string(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _native_already_running_notice(title: str, message: str) -> None:
    """Best-effort native duplicate-instance notice without a GUI toolkit dependency."""
    try:
        if PLATFORM == "windows":
            import ctypes

            # MB_OK | MB_ICONWARNING
            ctypes.windll.user32.MessageBoxW(None, message, title, 0x00000030)
            return
        if PLATFORM == "mac" and shutil.which("osascript"):
            script = (
                f"display alert {_apple_script_string(title)} "
                f"message {_apple_script_string(message)} as warning"
            )
            subprocess.run(
                ["osascript", "-e", script],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        zenity = shutil.which("zenity")
        if zenity:
            subprocess.run(
                [zenity, "--warning", f"--title={title}", f"--text={message}"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        kdialog = shutil.which("kdialog")
        if kdialog:
            subprocess.run(
                [kdialog, "--title", title, "--sorry", message],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
    except Exception:
        pass
    print(f"{title}: {message}", file=sys.stderr)


def _show_already_running() -> None:
    _native_already_running_notice(t("netshare_player_title"), t("already_running_message"))
    raise SystemExit(0)


def _ensure_single_instance_windows() -> None:
    global _win_mutex_handle
    import ctypes

    error_already_exists = 183
    handle = ctypes.windll.kernel32.CreateMutexW(
        None, False, "Global\\NetSharePlayer_SingleInstance_v1"
    )
    err = ctypes.windll.kernel32.GetLastError()
    if err == error_already_exists:
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        _show_already_running()
    _win_mutex_handle = handle


def _ensure_single_instance_linux() -> None:
    global _linux_lock_sock
    import socket as _sock

    lock_name = b"\x00NetSharePlayer_SingleInstance_v1"
    sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    try:
        sock.bind(lock_name)
    except OSError:
        sock.close()
        _show_already_running()
    _linux_lock_sock = sock


def _cleanup_lockfile() -> None:
    try:
        _LOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def _ensure_single_instance_lockfile() -> None:
    if _LOCK_FILE.exists():
        try:
            pid = int(_LOCK_FILE.read_text().strip())
            os.kill(pid, 0)
            _show_already_running()
        except (ProcessLookupError, PermissionError):
            pass
        except ValueError:
            pass
    _LOCK_FILE.write_text(str(os.getpid()))
    atexit.register(_cleanup_lockfile)


def ensure_single_instance() -> None:
    """Prevent more than one instance of the app from running at once."""
    if PLATFORM == "windows":
        _ensure_single_instance_windows()
    elif PLATFORM == "linux":
        _ensure_single_instance_linux()
    else:
        _ensure_single_instance_lockfile()
