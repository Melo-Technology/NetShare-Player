"""Cached audio peak extraction for the SoundCloud-style player waveform."""

from __future__ import annotations

from array import array
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

from src.deps import FFMPEG_BIN, HAS_FFMPEG


_CACHE_ROOT = (
    Path(os.environ["APPDATA"]) / "NetShare Player" / "waveforms"
    if os.environ.get("APPDATA")
    else Path.home() / ".netshare-player" / "waveforms"
)
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _cache_key(path: Path, samples: int) -> str:
    stat = path.stat()
    material = f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}|{samples}|v2"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _lock_for(key: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="wave_", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, separators=(",", ":"))
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def extract_waveform(path: Path, samples: int = 160) -> list[float]:
    """Return normalized mono peaks, decoding only 400 samples/second."""
    if not HAS_FFMPEG or not FFMPEG_BIN:
        raise RuntimeError("ffmpeg is not available")
    samples = max(32, min(int(samples), 4096))
    key = _cache_key(path, samples)
    cache_path = _CACHE_ROOT / f"{key}.json"

    with _lock_for(key):
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            peaks = cached.get("peaks")
            if isinstance(peaks, list) and len(peaks) == samples:
                return [float(value) for value in peaks]
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass

        result = subprocess.run(
            [
                FFMPEG_BIN,
                "-v", "error",
                "-i", str(path),
                "-vn",
                "-ac", "1",
                "-ar", "400",
                "-f", "s16le",
                "pipe:1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
            check=False,
        )
        if result.returncode != 0 or not result.stdout:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(message or "audio decoding failed")

        pcm = array("h")
        pcm.frombytes(result.stdout[: len(result.stdout) - len(result.stdout) % 2])
        if sys.byteorder != "little":
            pcm.byteswap()
        if not pcm:
            raise RuntimeError("audio contains no decodable samples")

        levels: list[float] = []
        for index in range(samples):
            start = index * len(pcm) // samples
            end = max(start + 1, (index + 1) * len(pcm) // samples)
            chunk = pcm[start:min(end, len(pcm))]
            # RMS preserves the perceived energy of each section. Taking only
            # the maximum makes nearly every bucket look equally loud.
            energy = sum(float(value) * value for value in chunk)
            levels.append(math.sqrt(energy / len(chunk)) if chunk else 0.0)

        ordered = sorted(levels)
        ceiling = ordered[min(len(ordered) - 1, int(len(ordered) * 0.96))]
        floor = ordered[min(len(ordered) - 1, int(len(ordered) * 0.08))]
        spread = ceiling - floor
        if ceiling <= 0 or spread <= 0:
            normalized = [0.0] * samples
        else:
            normalized = [
                round(max(0.06, min(1.0, (value - floor) / spread)), 4)
                for value in levels
            ]
        _atomic_write(cache_path, {"samples": samples, "peaks": normalized})
        return normalized
