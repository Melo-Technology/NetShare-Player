"""Best-effort native notifications without adding a desktop-toolkit dependency."""
from __future__ import annotations

import shutil
import subprocess

from src.utils.platform import PLATFORM


def _apple_script_string(value: str) -> str:
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'


def notify_system(title: str, message: str) -> bool:
    clean_title = str(title or "NetShare")[:96]
    clean_message = str(message or "")[:320]
    try:
        if PLATFORM == "mac":
            osascript = shutil.which("osascript")
            if not osascript:
                return False
            script = f"display notification {_apple_script_string(clean_message)} with title {_apple_script_string(clean_title)}"
            subprocess.Popen(
                [osascript, "-e", script],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        if PLATFORM == "linux":
            notify_send = shutil.which("notify-send")
            if not notify_send:
                return False
            subprocess.Popen(
                [notify_send, "--app-name=NetShare Server", clean_title, clean_message],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        if PLATFORM == "windows":
            powershell = shutil.which("powershell") or shutil.which("pwsh")
            if not powershell:
                return False
            # Values are passed through PowerShell's single-quoted string form;
            # every single quote is doubled so attacker-controlled paths/IPs
            # cannot become executable script.
            title_ps = clean_title.replace("'", "''")
            message_ps = clean_message.replace("'", "''")
            script = (
                "Add-Type -AssemblyName System.Windows.Forms;"
                "$n=New-Object System.Windows.Forms.NotifyIcon;"
                "$n.Icon=[System.Drawing.SystemIcons]::Information;"
                f"$n.BalloonTipTitle='{title_ps}';"
                f"$n.BalloonTipText='{message_ps}';"
                "$n.Visible=$true;$n.ShowBalloonTip(5000);Start-Sleep -Milliseconds 5500;$n.Dispose();"
            )
            subprocess.Popen(
                [powershell, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    except Exception:
        return False
    return False


__all__ = ["notify_system"]
