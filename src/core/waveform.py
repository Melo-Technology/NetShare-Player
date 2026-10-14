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
import time

from src.deps import FFMPEG_BIN, HAS_FFMPEG
from src.core.data_vault import secure_unlink
from src.core.vault_storage import read_json, write_json


_CACHE_ROOT = (
    Path(os.environ["APPDATA"]) / "NetShare Player" / "waveforms"
    if os.environ.get("APPDATA")
    else Path.home() / ".netshare-player" / "waveforms"
)
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()
_cleanup_guard = threading.Lock()
_last_cleanup_monotonic = 0.0
_CLEANUP_INTERVAL_SECONDS = 6 * 60 * 60


def _max_unused_days() -> int:
    try:
        return max(1, int(os.environ.get("NETSHARE_CACHE_MAX_UNUSED_DAYS", "60")))
    except (TypeError, ValueError):
        return 60


def cleanup_waveform_cache(*, max_unused_days: int | None = None, force: bool = False) -> dict[str, int]:
    """Purge waveform entries not consulted within the retention window.

    Cache-file mtime is touched on every hit. Automatic calls are throttled so
    normal playback never scans the cache directory more than once per six
    hours; tests/maintenance can request ``force=True``.
    """
    global _last_cleanup_monotonic
    now_mono = time.monotonic()
    with _cleanup_guard:
        if not force and _last_cleanup_monotonic and now_mono - _last_cleanup_monotonic < _CLEANUP_INTERVAL_SECONDS:
            return {"files": 0, "bytes": 0}
        _last_cleanup_monotonic = now_mono

    days = _max_unused_days() if max_unused_days is None else max(1, int(max_unused_days))
    cutoff = time.time() - (days * 24 * 60 * 60)
    removed_files = 0
    removed_bytes = 0
    try:
        entries = list(_CACHE_ROOT.glob("*.json")) if _CACHE_ROOT.exists() else []
    except OSError:
        entries = []
    for path in entries:
        try:
            if path.stat().st_mtime >= cutoff:
                continue
            key = path.stem
            lock = _lock_for(key)
            if not lock.acquire(blocking=False):
                continue
            try:
                stat = path.stat()
                if stat.st_mtime >= cutoff:
                    continue
                size = int(stat.st_size)
                secure_unlink(path)
                removed_files += 1
                removed_bytes += size
            finally:
                lock.release()
        except (FileNotFoundError, OSError):
            continue
    return {"files": removed_files, "bytes": removed_bytes}


def _cache_key(path: Path, samples: int) -> str:
    stat = path.stat()
    material = f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}|{samples}|v2"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _lock_for(key: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def _atomic_write(path: Path, payload: dict) -> None:
    write_json(path, payload, purpose=f"waveform:{path.stem}")


def extract_waveform(path: Path, samples: int = 160) -> list[float]:
    """Return normalized mono peaks, decoding only 400 samples/second."""
    if not HAS_FFMPEG or not FFMPEG_BIN:
        raise RuntimeError("ffmpeg is not available")
    samples = max(32, min(int(samples), 4096))
    key = _cache_key(path, samples)
    cache_path = _CACHE_ROOT / f"{key}.json"
    cleanup_waveform_cache()

    with _lock_for(key):
        try:
            cached = read_json(cache_path, purpose=f"waveform:{key}", default={})
            peaks = cached.get("peaks")
            if isinstance(peaks, list) and len(peaks) == samples:
                try: os.utime(cache_path, None)
                except OSError: pass
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


def clear_waveform_cache() -> dict[str, int]:
    """Remove generated waveform JSON files when no waveform job is active."""
    with _locks_guard:
        busy = any(lock.locked() for lock in _locks.values())
    if busy:
        raise RuntimeError("waveform generation is active")
    removed_files = 0
    removed_bytes = 0
    try:
        entries = list(_CACHE_ROOT.iterdir()) if _CACHE_ROOT.exists() else []
    except OSError:
        entries = []
    for path in entries:
        if not path.is_file():
            continue
        try:
            size = int(path.stat().st_size)
            secure_unlink(path)
            removed_files += 1
            removed_bytes += size
        except OSError:
            continue
    try:
        _CACHE_ROOT.rmdir()
    except OSError:
        pass
    return {"files": removed_files, "bytes": removed_bytes}
