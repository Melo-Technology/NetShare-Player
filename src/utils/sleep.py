"""Cross-platform helpers that prevent the host from sleeping while the server runs."""

import subprocess

import src.state as state
from src.utils.platform import PLATFORM

_sleep_inhibited    = False
_sleep_inhibit_proc = None   # subprocess on mac / linux


def inhibit_sleep(enable: bool) -> None:
    global _sleep_inhibited, _sleep_inhibit_proc

    if enable == _sleep_inhibited:
        return

    if PLATFORM == "windows":
        import ctypes
        ES_CONTINUOUS      = 0x80000000
        ES_SYSTEM_REQUIRED = 0x00000001
        if enable:
            ctypes.windll.kernel32.SetThreadExecutionState(
                ES_CONTINUOUS | ES_SYSTEM_REQUIRED
            )
        else:
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)

    elif PLATFORM == "mac":
        if enable:
            try:
                _sleep_inhibit_proc = subprocess.Popen(
                    ["caffeinate", "-d", "-i"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                state._emit("SLEEP  caffeinate not found", "dim")
        else:
            if _sleep_inhibit_proc:
                try:
                    _sleep_inhibit_proc.terminate()
                except Exception:
                    pass
                _sleep_inhibit_proc = None

    else:  # Linux
        if enable:
            try:
                _sleep_inhibit_proc = subprocess.Popen(
                    [
                        "systemd-inhibit",
                        "--what=sleep:idle",
                        "--who=NetShare Server",
                        "--why=Server is running",
                        "--mode=block",
                        "sleep", "infinity",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                state._emit(
                    "SLEEP  systemd-inhibit not found - install systemd or xdg-utils",
                    "dim",
                )
        else:
            if _sleep_inhibit_proc:
                try:
                    _sleep_inhibit_proc.terminate()
                except Exception:
                    pass
                _sleep_inhibit_proc = None

    _sleep_inhibited = enable
    state._emit(
        f"SLEEP  inhibitor {'ON' if enable else 'OFF'}",
        "ok" if enable else "dim",
    )
