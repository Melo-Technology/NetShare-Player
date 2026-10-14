"""User-initiated FFmpeg installation helper.

NetShare does not bundle or redistribute FFmpeg. This module only opens the
platform's command-line package manager with a fixed install command selected
for the current OS. The package manager and the installed FFmpeg build remain
third-party software governed by their own licenses.
"""

from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class FfmpegInstallPlan:
    os_family: str
    manager: str | None
    command: str | None
    supported: bool
    requires_admin: bool
    terminal: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "os_family": self.os_family,
            "manager": self.manager,
            "command": self.command,
            "supported": self.supported,
            "requires_admin": self.requires_admin,
            "terminal": self.terminal,
        }


class FfmpegInstallRuntime:
    """Build and launch a fixed, user-visible FFmpeg package-manager command."""

    def __init__(self, *, which: Callable[[str], str | None] = shutil.which) -> None:
        self._which = which

    def plan(self) -> FfmpegInstallPlan:
        system = platform.system().lower()
        if system == "windows":
            if self._which("winget"):
                return FfmpegInstallPlan(
                    os_family="windows",
                    manager="winget",
                    command="winget install --id Gyan.FFmpeg --exact",
                    supported=True,
                    requires_admin=False,
                    terminal="cmd.exe",
                )
            return FfmpegInstallPlan("windows", None, None, False, False, None)

        if system == "darwin":
            if self._which("brew"):
                return FfmpegInstallPlan("macos", "homebrew", "brew install ffmpeg", True, False, "Terminal")
            if self._which("port"):
                return FfmpegInstallPlan("macos", "macports", "sudo port install ffmpeg", True, True, "Terminal")
            return FfmpegInstallPlan("macos", None, None, False, False, None)

        if system == "linux":
            managers = (
                ("apt-get", "apt", "sudo apt-get update && sudo apt-get install -y ffmpeg", True),
                ("dnf", "dnf", "sudo dnf install -y ffmpeg", True),
                ("pacman", "pacman", "sudo pacman -S --needed ffmpeg", True),
                ("zypper", "zypper", "sudo zypper install -y ffmpeg", True),
                ("apk", "apk", "sudo apk add ffmpeg", True),
            )
            for executable, manager, command, requires_admin in managers:
                if self._which(executable):
                    terminal = self._find_linux_terminal()
                    return FfmpegInstallPlan("linux", manager, command, bool(terminal), requires_admin, terminal)
            return FfmpegInstallPlan("linux", None, None, False, False, self._find_linux_terminal())

        return FfmpegInstallPlan(system or "unknown", None, None, False, False, None)

    def launch(self) -> dict[str, object]:
        plan = self.plan()
        result = plan.to_dict()
        result["started"] = False
        if not plan.supported or not plan.command:
            result["reason"] = "package_manager_unavailable"
            return result

        try:
            if plan.os_family == "windows":
                creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
                subprocess.Popen(["cmd.exe", "/k", plan.command], creationflags=creationflags)
            elif plan.os_family == "macos":
                escaped = plan.command.replace("\\", "\\\\").replace('"', '\\"')
                script = f'tell application "Terminal" to do script "{escaped}"'
                subprocess.Popen(["osascript", "-e", script, "-e", 'tell application "Terminal" to activate'])
            elif plan.os_family == "linux":
                self._launch_linux(plan.terminal or "", plan.command)
            else:
                result["reason"] = "unsupported_os"
                return result
        except Exception as exc:
            result["reason"] = "launch_failed"
            result["error_type"] = type(exc).__name__
            return result

        result["started"] = True
        return result

    def _find_linux_terminal(self) -> str | None:
        for name in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"):
            path = self._which(name)
            if path:
                return path
        return None

    @staticmethod
    def _launch_linux(terminal: str, command: str) -> None:
        tail = f"{command}; printf '\\n'; exec sh"
        name = os.path.basename(terminal)
        if name == "gnome-terminal":
            args = [terminal, "--", "sh", "-lc", tail]
        elif name == "xfce4-terminal":
            args = [terminal, "--command", f"sh -lc {shlex.quote(tail)}"]
        else:
            args = [terminal, "-e", "sh", "-lc", tail]
        subprocess.Popen(args)


ffmpeg_install_runtime = FfmpegInstallRuntime()
