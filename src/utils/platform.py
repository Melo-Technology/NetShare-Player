"""Platform detection helpers and single-instance protection for the app."""

import atexit
import os
import sys
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import messagebox
from src.i18n import t


# Platform detection

def _get_platform() -> str:
    p = sys.platform
    if p == "darwin":        return "mac"
    elif p.startswith("win"): return "windows"
    else:                     return "linux"

PLATFORM: str = _get_platform()


# Single-instance helpers

_win_mutex_handle  = None
_linux_lock_sock   = None
_LOCK_FILE         = Path(tempfile.gettempdir()) / "netshare_player_v1.lock"


def _show_already_running():
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning(t("netshare_player_title"), t("already_running_message"))
    root.destroy()
    sys.exit(0)


def _ensure_single_instance_windows():
    global _win_mutex_handle
    import ctypes
    ERROR_ALREADY_EXISTS = 183
    handle = ctypes.windll.kernel32.CreateMutexW(
        None, False, "Global\\NetSharePlayer_SingleInstance_v1"
    )
    err = ctypes.windll.kernel32.GetLastError()
    if err == ERROR_ALREADY_EXISTS:
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        _show_already_running()
    _win_mutex_handle = handle


def _ensure_single_instance_linux():
    global _linux_lock_sock
    import socket as _sock
    LOCK_NAME = b"\x00NetSharePlayer_SingleInstance_v1"
    sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    try:
        sock.bind(LOCK_NAME)
    except OSError:
        sock.close()
        _show_already_running()
    _linux_lock_sock = sock


def _cleanup_lockfile():
    try:
        _LOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def _ensure_single_instance_lockfile():
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


def ensure_single_instance():
    """Prevent more than one instance of the app from running at once."""
    if PLATFORM == "windows":
        _ensure_single_instance_windows()
    elif PLATFORM == "linux":
        _ensure_single_instance_linux()
    else:
        _ensure_single_instance_lockfile()
