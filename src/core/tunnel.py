"""Management for the public localhost.run reverse tunnel used by the server."""

import re
import subprocess
import threading
import time as _time
from typing import Callable

import src.state as state
from src.utils.platform import PLATFORM


class PublicTunnel:

    _URL_PATTERN = re.compile(r"https://[a-zA-Z0-9\-]+\.lhr\.life")
    _RETRY_DELAYS = [3, 6, 12, 30]

    def __init__(self, port: int):
        self._port = port
        self._process: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None

        self._on_url: Callable | None = None
        self._on_error: Callable | None = None
        self._on_stop: Callable | None = None
        self._on_reconnecting: Callable | None = None

        self._active = False
        self._attempt = 0
        self._last_url = ""

    def start(
        self,
        on_url: Callable | None = None,
        on_error: Callable | None = None,
        on_stop: Callable | None = None,
        on_reconnecting: Callable | None = None,
    ):
        self._on_url = on_url
        self._on_error = on_error
        self._on_stop = on_stop
        self._on_reconnecting = on_reconnecting
        self._active = True
        self._attempt = 0
        self._last_url = ""
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="tunnel"
        )
        self._thread.start()

    def stop(self):
        self._active = False
        self._kill_process()

    def _kill_process(self):
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

    def _build_cmd(self, ssh_bin: str) -> list[str]:
        return [
            ssh_bin,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "TCPKeepAlive=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-R", f"80:127.0.0.1:{self._port}",
            "nokey@localhost.run",
        ]

    def _find_ssh(self) -> str | None:
        candidates = ["ssh"]
        if PLATFORM == "windows":
            candidates += [
                r"C:\Windows\System32\OpenSSH\ssh.exe",
                r"C:\Program Files\Git\usr\bin\ssh.exe",
            ]
        for ssh_bin in candidates:
            try:
                subprocess.run([ssh_bin, "-V"], capture_output=True, timeout=3)
                return ssh_bin
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue
        return None

    def _log_prefix(self) -> str:
        return "TUNNEL"

    def _find_executable(self) -> str | None:
        return self._find_ssh()

    def _missing_executable_message(self) -> str:
        return "SSH not found - install OpenSSH or Git for Windows"

    def _run_loop(self):
        executable = self._find_executable()
        prefix = self._log_prefix()
        if executable is None:
            msg = self._missing_executable_message()
            state._emit(f"{prefix} {msg}", "error")
            if self._on_error:
                self._on_error(msg)
            return

        while self._active:
            self._attempt += 1
            if self._attempt > 1:
                delay_idx = min(self._attempt - 2, len(self._RETRY_DELAYS) - 1)
                delay = self._RETRY_DELAYS[delay_idx]
                state._emit(f"{prefix} reconnecting in {delay}s  (attempt {self._attempt})...", "dim")
                if self._on_reconnecting:
                    self._on_reconnecting(delay, self._attempt)
                for _ in range(delay * 2):
                    if not self._active:
                        return
                    _time.sleep(0.5)
                if not self._active:
                    return

            success = self._run_once(executable)
            if not self._active:
                break
            if not success and self._attempt == 1:
                break

        if self._on_stop:
            self._on_stop()

    def _run_once(self, ssh_bin: str) -> bool:
        state._emit("TUNNEL starting localhost.run tunnel...", "dim")
        try:
            proc = subprocess.Popen(
                self._build_cmd(ssh_bin),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            state._emit(f"TUNNEL failed to start SSH: {e}", "error")
            if self._on_error:
                self._on_error(str(e))
            return False

        self._process = proc
        url_found = False

        try:
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                state._emit(f"TUNNEL {line}", "dim")
                match = self._URL_PATTERN.search(line)
                if match:
                    public_url = match.group(0)
                    url_found = True
                    if public_url != self._last_url:
                        self._last_url = public_url
                        state._emit(f"TUNNEL public URL -> {public_url}", "ok")
                        if self._on_url:
                            self._on_url(public_url)
        except Exception as e:
            if self._active:
                state._emit(f"TUNNEL read error: {e}", "error")
        finally:
            rc = proc.wait() if proc.poll() is None else proc.returncode
            if self._active:
                state._emit(f"TUNNEL process exited (rc={rc})", "dim")
            self._process = None

        return url_found
