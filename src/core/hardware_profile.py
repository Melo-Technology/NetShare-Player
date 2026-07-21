"""Lightweight hardware capability detection for adaptive server workloads."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class HardwareProfile:
    name: str
    cpu_count: int
    workers: int
    bpm_enabled: bool
    nvidia_detected: bool = False
    nvidia_name: str | None = None


def _detect_nvidia(timeout: float = 2.0) -> tuple[bool, str | None]:
    """Detect a usable NVIDIA driver CLI without adding a GPU dependency."""
    executable = shutil.which("nvidia-smi") or shutil.which("nvidia-smi.exe")
    if not executable:
        return False, None
    try:
        result = subprocess.run(
            [executable, "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return result.returncode == 0 and bool(names), ", ".join(names) or None
    except (OSError, subprocess.SubprocessError):
        return False, None


def detect_hardware_profile() -> HardwareProfile:
    cpu_count = max(1, os.cpu_count() or 1)
    standard = cpu_count >= 4
    gpu, gpu_name = _detect_nvidia()
    return HardwareProfile(
        name="standard" if standard else "eco",
        cpu_count=cpu_count,
        workers=max(1, cpu_count - 1) if standard else min(2, cpu_count),
        bpm_enabled=standard,
        nvidia_detected=gpu,
        nvidia_name=gpu_name,
    )


HARDWARE_PROFILE = detect_hardware_profile()

