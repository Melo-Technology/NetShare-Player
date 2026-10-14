"""Bounded probing and WebVTT extraction for embedded video tracks."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import src.deps as deps

TRACK_CACHE_TTL_SECONDS = 15 * 60
MAX_TRACK_CACHE_ENTRIES = 256
PROBE_TIMEOUT_SECONDS = 20
EXTRACT_TIMEOUT_SECONDS = 30
AUDIO_CONVERSION_TIMEOUT_SECONDS = 8
_cache_lock = threading.RLock()
_track_cache: dict[tuple[str, int, int], tuple[float, "EmbeddedTrackInventory"]] = {}
_hls_audio_cache: dict[
    tuple[str, int, int, str], tuple[float, tuple["EmbeddedTrack", ...]]
] = {}


class SubtitleFailure(str, Enum):
    TRACK_ABSENT = "track_absent"
    EXTRACTION_FAILED = "extraction_failed"
    FORMAT_NOT_CONVERTIBLE = "format_not_convertible"


class EmbeddedTrackError(RuntimeError):
    def __init__(self, message: str, *, reason=SubtitleFailure.EXTRACTION_FAILED):
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class EmbeddedTrack:
    index: int
    kind: str
    codec: str
    language: str | None
    title: str | None
    default: bool

    def as_json(self) -> dict:
        return {
            "index": self.index,
            "kind": self.kind,
            "codec": self.codec,
            "language": self.language,
            "title": self.title,
            "default": self.default,
        }


@dataclass(frozen=True)
class EmbeddedTrackInventory:
    video: tuple[EmbeddedTrack, ...] = ()
    audio: tuple[EmbeddedTrack, ...] = ()
    subtitles: tuple[EmbeddedTrack, ...] = ()

    def as_json(self) -> dict:
        return {
            "video": [track.as_json() for track in self.video],
            "audio": [track.as_json() for track in self.audio],
            "subtitles": [track.as_json() for track in self.subtitles],
        }

    def requires_hls(self, path: Path) -> bool:
        """Return whether browser playback must use transcoded HLS."""
        if path.suffix.lower() not in {".mp4", ".m4v", ".webm", ".ogv"}:
            return True
        if not self.video:
            return True
        if any(track.codec.lower() not in {"h264", "vp8", "vp9", "av1"}
               for track in self.video):
            return True
        return any(track.codec.lower() not in {"aac", "mp3", "opus", "vorbis", "flac"}
                   for track in self.audio)


def _cache_key(path: Path) -> tuple[str, int, int]:
    stat = path.stat()
    return str(path.resolve()), stat.st_mtime_ns, stat.st_size


def probe_embedded_tracks(path: Path) -> EmbeddedTrackInventory:
    if not deps.FFPROBE_BIN:
        return EmbeddedTrackInventory()
    key = _cache_key(path)
    now = time.monotonic()
    with _cache_lock:
        cached = _track_cache.get(key)
        if cached and now - cached[0] <= TRACK_CACHE_TTL_SECONDS:
            return cached[1]
    try:
        completed = subprocess.run(
            [str(deps.FFPROBE_BIN), "-v", "error", "-show_streams", "-of", "json", str(path)],
            capture_output=True, check=False, timeout=PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EmbeddedTrackError("embedded track probe unavailable") from error
    if completed.returncode != 0:
        raise EmbeddedTrackError("embedded track probe failed")
    try:
        streams = json.loads(completed.stdout.decode("utf-8"))["streams"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise EmbeddedTrackError("invalid embedded track descriptor") from error
    video: list[EmbeddedTrack] = []
    audio: list[EmbeddedTrack] = []
    subtitles: list[EmbeddedTrack] = []
    for stream in streams:
        kind = stream.get("codec_type")
        if kind not in {"video", "audio", "subtitle"}:
            continue
        tags = stream.get("tags") if isinstance(stream.get("tags"), dict) else {}
        disposition = stream.get("disposition") if isinstance(stream.get("disposition"), dict) else {}
        track = EmbeddedTrack(
            index=int(stream["index"]), kind=kind,
            codec=str(stream.get("codec_name") or "unknown"),
            language=str(tags["language"]) if tags.get("language") else None,
            title=str(tags["title"]) if tags.get("title") else None,
            default=disposition.get("default") == 1,
        )
        if kind == "video":
            video.append(track)
        elif kind == "audio":
            audio.append(track)
        else:
            subtitles.append(track)
    inventory = EmbeddedTrackInventory(
        video=tuple(video), audio=tuple(audio), subtitles=tuple(subtitles),
    )
    with _cache_lock:
        _track_cache[key] = (now, inventory)
        if len(_track_cache) > MAX_TRACK_CACHE_ENTRIES:
            oldest = min(_track_cache, key=lambda item: _track_cache[item][0])
            _track_cache.pop(oldest, None)
    return inventory


def _audio_track_converts_to_aac(path: Path, stream_index: int) -> bool:
    if not deps.FFMPEG_BIN:
        return False
    try:
        completed = subprocess.run(
            [
                str(deps.FFMPEG_BIN), "-hide_banner", "-loglevel", "error",
                "-nostdin", "-i", str(path), "-map", f"0:{stream_index}",
                "-frames:a", "1", "-vn", "-c:a", "aac", "-f", "null", "-",
            ],
            capture_output=True, check=False,
            timeout=AUDIO_CONVERSION_TIMEOUT_SECONDS,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def probe_hls_tracks(path: Path) -> EmbeddedTrackInventory:
    """Return tracks whose audio streams FFmpeg can actually convert to AAC."""
    inventory = probe_embedded_tracks(path)
    if not inventory.audio:
        return inventory
    file_key = _cache_key(path)
    key = (*file_key, os.path.normcase(os.path.abspath(str(deps.FFMPEG_BIN or ""))))
    now = time.monotonic()
    with _cache_lock:
        cached = _hls_audio_cache.get(key)
        if cached and now - cached[0] <= TRACK_CACHE_TTL_SECONDS:
            convertible = cached[1]
        else:
            convertible = None
    if convertible is None:
        convertible = tuple(
            track for track in inventory.audio
            if _audio_track_converts_to_aac(path, track.index)
        )
        with _cache_lock:
            _hls_audio_cache[key] = (now, convertible)
            if len(_hls_audio_cache) > MAX_TRACK_CACHE_ENTRIES:
                oldest = min(_hls_audio_cache, key=lambda item: _hls_audio_cache[item][0])
                _hls_audio_cache.pop(oldest, None)
    return EmbeddedTrackInventory(
        video=inventory.video, audio=convertible, subtitles=inventory.subtitles,
    )


def extract_webvtt(path: Path, stream_index: int) -> bytes:
    inventory = probe_embedded_tracks(path)
    track = next((track for track in inventory.subtitles if track.index == stream_index), None)
    if track is None:
        raise EmbeddedTrackError("subtitle track unavailable", reason=SubtitleFailure.TRACK_ABSENT)
    # Bitmap subtitles need OCR, which the WebVTT extraction path does not provide.
    if track.codec.lower() in {"hdmv_pgs_subtitle", "dvd_subtitle", "dvb_subtitle", "xsub"}:
        raise EmbeddedTrackError(
            "subtitle format not convertible", reason=SubtitleFailure.FORMAT_NOT_CONVERTIBLE,
        )
    if not deps.FFMPEG_BIN:
        raise EmbeddedTrackError("subtitle conversion unavailable")
    descriptor, name = tempfile.mkstemp(prefix="netshare-subtitle-", suffix=".vtt")
    os.close(descriptor)
    temporary = Path(name)
    try:
        completed = subprocess.run(
            [str(deps.FFMPEG_BIN), "-v", "error", "-nostdin", "-y", "-i", str(path),
             "-map", f"0:{stream_index}", "-f", "webvtt", str(temporary)],
            capture_output=True, check=False, timeout=EXTRACT_TIMEOUT_SECONDS,
        )
        if completed.returncode != 0 or not temporary.exists():
            raise EmbeddedTrackError("subtitle conversion failed")
        payload = temporary.read_bytes()
        if not payload.startswith(b"WEBVTT"):
            raise EmbeddedTrackError("invalid WebVTT output")
        return payload
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EmbeddedTrackError("subtitle conversion unavailable") from error
    finally:
        temporary.unlink(missing_ok=True)


def clear_embedded_track_cache() -> dict[str, int]:
    """Drop all in-memory ffprobe/track convertibility cache entries."""
    with _cache_lock:
        tracks = len(_track_cache)
        hls_audio = len(_hls_audio_cache)
        _track_cache.clear()
        _hls_audio_cache.clear()
    return {"track_entries": tracks, "hls_audio_entries": hls_audio}
