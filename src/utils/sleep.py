"""Reliable cross-platform system-sleep inhibition for the desktop server.

The inhibitor is intentionally process scoped.  Windows needs the call to
``SetThreadExecutionState`` to be made and released by the same long-lived
thread, while macOS/Linux use OS helpers whose child command watches the parent
PID so an abrupt NetShare exit cannot leave a permanent inhibitor behind.
"""
from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Callable

from src.utils.platform import PLATFORM


def _emit(message: str, kind: str = "info") -> None:
    try:
        import src.state as state
        state._emit(message, kind)
    except Exception:
        pass


class SleepInhibitor:
    """Own exactly one OS sleep inhibitor with idempotent, thread-safe control."""

    def __init__(
        self,
        *,
        platform: str = PLATFORM,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
        which: Callable[[str], str | None] = shutil.which,
        monitor_interval: float = 5.0,
    ) -> None:
        self.platform = str(platform)
        self._popen = popen
        self._which = which
        self._monitor_interval = max(0.25, float(monitor_interval))
        self._lock = threading.RLock()
        self._requested = False
        self._active = False
        self._backend = "none"
        self._last_error: str | None = None
        self._process: subprocess.Popen | None = None
        self._worker: threading.Thread | None = None
        self._stop_event: threading.Event | None = None

    def set_enabled(self, enabled: bool) -> dict[str, Any]:
        desired = bool(enabled)
        with self._lock:
            if desired == self._requested and (not desired or self._is_active_locked()):
                return self._snapshot_locked()
            self._requested = desired
        if desired:
            self._start()
        else:
            self._stop()
        return self.status()

    def release(self) -> dict[str, Any]:
        return self.set_enabled(False)

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._active = self._is_active_locked()
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict[str, Any]:
        return {
            "requested": bool(self._requested),
            "active": bool(self._active),
            "backend": str(self._backend),
            "platform": str(self.platform),
            "error": self._last_error,
        }

    def _is_active_locked(self) -> bool:
        if not self._requested:
            return False
        if self.platform == "windows":
            return bool(self._worker and self._worker.is_alive() and self._active)
        process = self._process
        if process is None:
            return False
        try:
            return process.poll() is None
        except Exception:
            return False

    def _start(self) -> None:
        with self._lock:
            self._last_error = None
            self._active = False
            stop = threading.Event()
            self._stop_event = stop
        if self.platform == "windows":
            thread = threading.Thread(
                target=self._windows_worker,
                args=(stop,),
                name="NetShareSleepInhibitor",
                daemon=True,
            )
            with self._lock:
                self._backend = "SetThreadExecutionState"
                self._worker = thread
            thread.start()
            # Give the dedicated thread a short opportunity to call the API so
            # the Settings UI can report a truthful state immediately.
            deadline = time.monotonic() + 0.75
            while time.monotonic() < deadline:
                with self._lock:
                    if self._active or self._last_error:
                        break
                time.sleep(0.01)
            return

        try:
            process, backend = self._spawn_posix_process()
        except Exception as exc:
            self._mark_failed(f"{type(exc).__name__}: {exc}")
            return
        with self._lock:
            if not self._requested:
                try:
                    process.terminate()
                except Exception:
                    pass
                return
            self._process = process
            self._backend = backend
            self._active = True
        _emit(f"SLEEP  inhibitor ON [{backend}]", "ok")
        monitor = threading.Thread(
            target=self._posix_monitor,
            args=(stop,),
            name="NetShareSleepInhibitorMonitor",
            daemon=True,
        )
        with self._lock:
            self._worker = monitor
        monitor.start()

    def _stop(self) -> None:
        with self._lock:
            stop = self._stop_event
            process = self._process
            worker = self._worker
            self._requested = False
            if stop is not None:
                stop.set()
        if process is not None:
            try:
                process.terminate()
            except Exception:
                pass
            try:
                process.wait(timeout=1.5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        if worker is not None and worker is not threading.current_thread() and worker.is_alive():
            worker.join(timeout=2.0)
        with self._lock:
            self._process = None
            self._worker = None
            self._stop_event = None
            self._active = False
            self._backend = "none"
            self._last_error = None
        _emit("SLEEP  inhibitor OFF", "dim")

    def _windows_worker(self, stop: threading.Event) -> None:
        ES_CONTINUOUS = 0x80000000
        ES_SYSTEM_REQUIRED = 0x00000001
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            previous = kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
            if not previous:
                raise OSError("SetThreadExecutionState returned 0")
            with self._lock:
                if self._requested:
                    self._active = True
                    self._last_error = None
            _emit("SLEEP  inhibitor ON [SetThreadExecutionState]", "ok")
            # The ES_CONTINUOUS state belongs to this thread.  Keeping this
            # exact thread alive is the critical difference from the old bridge
            # worker call which could disappear after the PyWebView invocation.
            while not stop.wait(30.0):
                if not self._requested:
                    break
                # Reassert periodically as a defensive measure around resume or
                # power-policy transitions. A failure is surfaced rather than
                # silently claiming Keep Alive is working.
                if not kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED):
                    raise OSError("SetThreadExecutionState refresh returned 0")
        except Exception as exc:
            self._mark_failed(f"{type(exc).__name__}: {exc}")
        finally:
            try:
                import ctypes
                ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
            except Exception:
                pass
            with self._lock:
                self._active = False

    def _parent_guard_command(self) -> list[str]:
        shell = self._which("sh") or "/bin/sh"
        # PID is decimal-only and passed as argv, not interpolated from user data.
        return [
            shell,
            "-c",
            'while kill -0 "$1" 2>/dev/null; do sleep 5; done',
            "netshare-parent-watch",
            str(os.getpid()),
        ]

    def _spawn_posix_process(self) -> tuple[subprocess.Popen, str]:
        guard = self._parent_guard_command()
        common = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "stdin": subprocess.DEVNULL,
        }
        if self.platform == "mac":
            caffeinate = self._which("caffeinate") or "/usr/bin/caffeinate"
            if not os.path.exists(caffeinate) and self._which("caffeinate") is None:
                raise FileNotFoundError("caffeinate not found")
            process = self._popen(
                [caffeinate, "-i", "-w", str(os.getpid())],
                **common,
            )
            return process, "caffeinate"

        inhibitor = self._which("systemd-inhibit")
        if inhibitor:
            process = self._popen(
                [
                    inhibitor,
                    "--what=sleep:idle",
                    "--who=NetShare Server",
                    "--why=NetShare server is sharing files",
                    "--mode=block",
                    *guard,
                ],
                **common,
            )
            return process, "systemd-inhibit"

        gnome = self._which("gnome-session-inhibit")
        if gnome:
            process = self._popen(
                [
                    gnome,
                    "--app-id=netshare-server",
                    "--reason=NetShare server is sharing files",
                    "--inhibit=suspend:idle",
                    *guard,
                ],
                **common,
            )
            return process, "gnome-session-inhibit"
        raise FileNotFoundError("no supported Linux sleep inhibitor found")

    def _posix_monitor(self, stop: threading.Event) -> None:
        failures = 0
        while not stop.wait(self._monitor_interval):
            with self._lock:
                if not self._requested:
                    return
                process = self._process
            if process is not None:
                try:
                    if process.poll() is None:
                        continue
                except Exception:
                    pass
            failures += 1
            if failures > 3:
                self._mark_failed("sleep inhibitor exited repeatedly")
                return
            # Unexpected helper exit while the app remains alive. Recreate it a
            # bounded number of times; never spin indefinitely.
            try:
                replacement, backend = self._spawn_posix_process()
            except Exception as exc:
                self._mark_failed(f"{type(exc).__name__}: {exc}")
                return
            with self._lock:
                if not self._requested:
                    try:
                        replacement.terminate()
                    except Exception:
                        pass
                    return
                self._process = replacement
                self._backend = backend
                self._active = True
            _emit(f"SLEEP  inhibitor restarted [{backend}]", "warning")

    def _mark_failed(self, message: str) -> None:
        clean = str(message)[:240]
        with self._lock:
            self._active = False
            self._last_error = clean
        _emit(f"SLEEP  inhibitor unavailable: {clean}", "warning")


sleep_inhibitor = SleepInhibitor()


def inhibit_sleep(enable: bool) -> dict[str, Any]:
    """Compatibility wrapper used by the Settings runtime."""
    return sleep_inhibitor.set_enabled(bool(enable))


def sleep_inhibitor_status() -> dict[str, Any]:
    return sleep_inhibitor.status()


def release_sleep_inhibitor() -> dict[str, Any]:
    return sleep_inhibitor.release()


atexit.register(release_sleep_inhibitor)

__all__ = [
    "SleepInhibitor",
    "sleep_inhibitor",
    "inhibit_sleep",
    "sleep_inhibitor_status",
    "release_sleep_inhibitor",
]
