"""Bounded media-derived resources shared by standalone and cluster routes."""

from __future__ import annotations

import json
import mimetypes
import queue
import subprocess
import sys
import threading
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from src.core.file_index import _file_index
from src.core.media_analysis import ANALYSIS_VERSION, is_audio
from src.core.thumbnail_cache import get_thumbnail_cache
from src.core.lyrics import lyrics_service, resolve_lyrics_query
import src.deps as deps
from src.deps import HAS_PIL
from src.utils.network import extract_cover_from_mp3, extract_id3_metadata

if HAS_PIL:
    from PIL import Image as PilImage

MAX_ART_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024
MAX_LYRICS_BYTES = 512 * 1024
MAX_THUMBNAIL_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024 * 1024
MAX_IMAGE_SOURCE_BYTES = 50 * 1024 * 1024
MAX_IMAGE_DIMENSION = 10_000
THUMBNAIL_QUEUE_SECONDS = 10.0
_SUBPROCESS_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _resample_waveform(waveform: list[float], samples: int) -> list[float]:
    """Resize indexed analysis bins while preserving both endpoints."""
    samples = max(32, min(int(samples), 4096))
    if not waveform:
        return []
    if len(waveform) == 1:
        return [round(float(waveform[0]), 4)] * samples
    if samples == len(waveform):
        return [float(value) for value in waveform]
    scale = (len(waveform) - 1) / (samples - 1)
    resized = []
    for index in range(samples):
        position = index * scale
        lower = int(position)
        upper = min(lower + 1, len(waveform) - 1)
        fraction = position - lower
        value = float(waveform[lower]) * (1.0 - fraction) + float(waveform[upper]) * fraction
        resized.append(round(value, 4))
    return resized


@dataclass(frozen=True)
class DerivedResource:
    status: int
    mime: str
    body: bytes


@dataclass
class _ThumbnailJob:
    target: Path
    width: int
    height: int
    started: threading.Event
    finished: threading.Event
    result: DerivedResource | None = None
    error: Exception | None = None
    cancelled: bool = False


class DerivedMediaService:
    """Use two FIFO thumbnail workers so modest Slaves remain responsive."""

    def __init__(self) -> None:
        self._thumbnail_jobs: queue.Queue[_ThumbnailJob] = queue.Queue()
        for index in range(2):
            threading.Thread(
                target=self._thumbnail_worker, daemon=True,
                name=f"netshare-thumbnail-{index + 1}",
            ).start()

    def artwork(self, target: Path) -> DerivedResource:
        result = extract_cover_from_mp3(target)
        if not result:
            return DerivedResource(404, "application/octet-stream", b"")
        body, mime = result
        if len(body) > MAX_ART_BYTES:
            return DerivedResource(413, "application/octet-stream", b"")
        return DerivedResource(200, mime, body)

    def lyrics(self, path: str, target: Path) -> DerivedResource:
        """Resolve bounded lyrics for a local or federated audio file.

        The operation intentionally runs on the content-owning node so metadata
        and premium/path checks stay on the Slave.  Only the bounded JSON result
        crosses the authenticated cluster channel.
        """
        try:
            metadata = extract_id3_metadata(target)
        except Exception:
            metadata = {}
        analysis = _file_index.get_analysis(path) or {}
        if not metadata.get("duration") and analysis.get("duration_seconds"):
            metadata["duration"] = analysis["duration_seconds"]
        query = resolve_lyrics_query(metadata, target.name)
        result = lyrics_service.lookup(**query)
        body = json.dumps(
            {"path": path, **result}, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(body) > MAX_LYRICS_BYTES:
            body = json.dumps({
                "path": path,
                "found": False,
                "plain_lyrics": None,
                "synced_lyrics": None,
                "instrumental": False,
                "source": None,
                "cached": bool(result.get("cached")),
                "error": "lyrics_too_large",
            }, separators=(",", ":")).encode("utf-8")
            return DerivedResource(413, "application/json; charset=utf-8", body)
        return DerivedResource(200, "application/json; charset=utf-8", body)

    def media_analysis(self, path: str, target: Path) -> DerivedResource:
        if target.stat().st_size > MAX_SOURCE_BYTES or not is_audio(target):
            return DerivedResource(404, "application/json", b"")
        if not deps.HAS_AUDIO_ANALYSIS:
            return self._audio_unavailable()
        analysis = _file_index.get_analysis(path)
        if analysis and analysis.get("analysis_error"):
            return self._audio_unavailable(analysis)
        if not analysis or analysis.get("analysis_version") != ANALYSIS_VERSION:
            _file_index.schedule_analysis(path, target)
            payload = {"status": "pending", "path": path}
            status = 202
        else:
            payload = {"status": "ready", "path": path, **analysis}
            status = 200
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_JSON_BYTES:
            return DerivedResource(413, "application/json", b"")
        return DerivedResource(status, "application/json; charset=utf-8", body)

    def waveform(self, path: str, target: Path, samples: int) -> DerivedResource:
        if target.stat().st_size > MAX_SOURCE_BYTES or not is_audio(target):
            return DerivedResource(404, "application/json", b"")
        if not deps.HAS_AUDIO_ANALYSIS:
            return self._audio_unavailable()
        analysis = _file_index.get_analysis(path)
        if analysis and analysis.get("analysis_error"):
            return self._audio_unavailable(analysis)
        waveform = analysis.get("waveform") if analysis else None
        if analysis and analysis.get("analysis_version") == ANALYSIS_VERSION and isinstance(waveform, list):
            payload = {"peaks": _resample_waveform(waveform, samples), "cached": True}
            status = 200
        else:
            # The legacy endpoint shares the background analysis pipeline so
            # it cannot start a second FFmpeg decode or maintain another cache.
            _file_index.schedule_analysis(path, target)
            payload = {"status": "pending", "path": path, "cached": False}
            status = 202
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_JSON_BYTES:
            return DerivedResource(413, "application/json", b"")
        return DerivedResource(status, "application/json; charset=utf-8", body)

    @staticmethod
    def _audio_unavailable(analysis: dict | None = None) -> DerivedResource:
        error = str((analysis or {}).get("analysis_error") or "ffmpeg_unavailable")
        message = str(
            (analysis or {}).get("analysis_error_message")
            or "Install a complete FFmpeg system package to enable audio analysis."
        )
        body = json.dumps({
            "status": "unavailable" if error == "ffmpeg_unavailable" else "error",
            "error": error,
            "message": message,
        }, separators=(",", ":")).encode("utf-8")
        return DerivedResource(
            501 if error == "ffmpeg_unavailable" else 422,
            "application/json; charset=utf-8",
            body,
        )

    def thumbnail(self, target: Path, width: int, height: int) -> DerivedResource:
        width, height = min(int(width), 600), min(int(height), 600)
        cache = get_thumbnail_cache()
        cache_key = cache.key(target, width, height)
        cached = cache.get(cache_key)
        if cached is not None:
            return DerivedResource(200, "image/jpeg", cached)
        job = _ThumbnailJob(
            target, width, height, threading.Event(), threading.Event(),
        )
        self._thumbnail_jobs.put(job)
        if not job.started.wait(THUMBNAIL_QUEUE_SECONDS):
            job.cancelled = True
            return DerivedResource(503, "application/octet-stream", b"")
        job.finished.wait(46.0)
        if job.error is not None:
            raise job.error
        return job.result or DerivedResource(504, "application/octet-stream", b"")

    def _thumbnail_worker(self) -> None:
        while True:
            job = self._thumbnail_jobs.get()
            try:
                if job.cancelled:
                    continue
                job.started.set()
                job.result = self._generate_thumbnail(
                    job.target, job.width, job.height,
                )
            except Exception as error:
                job.error = error
            finally:
                job.finished.set()
                self._thumbnail_jobs.task_done()

    @staticmethod
    def _generate_thumbnail(target: Path, width: int, height: int) -> DerivedResource:
        cache = get_thumbnail_cache()
        key = cache.key(target, width, height)
        extension = target.suffix.lstrip(".").lower()
        video_extensions = {
            "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v",
            "mpg", "mpeg", "3gp", "ts", "mts", "m2ts", "vob", "ogv",
            "rm", "rmvb",
        }
        if extension in video_extensions:
            if not deps.HAS_VIDEO_THUMBNAILS:
                body = json.dumps({
                    "status": "unavailable",
                    "error": "ffmpeg_unavailable",
                    "message": (
                        "Install a complete FFmpeg system package to enable "
                        "video thumbnails."
                    ),
                }, separators=(",", ":")).encode("utf-8")
                return DerivedResource(501, "application/json; charset=utf-8", body)
            data = b""
            for seek in ("00:00:05", "00:00:01", "00:00:00"):
                result = subprocess.run(
                    [str(deps.FFMPEG_BIN), "-loglevel", "error", "-ss", seek,
                     "-i", str(target), "-vframes", "1", "-vf",
                     f"scale='min({width},iw)':'min({height},ih)':force_original_aspect_ratio=decrease",
                     "-f", "image2", "-vcodec", "mjpeg", "pipe:1"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                    creationflags=_SUBPROCESS_FLAGS,
                )
                if result.returncode == 0 and result.stdout:
                    data = result.stdout
                    break
            if not data:
                return DerivedResource(422, "application/octet-stream", b"")
        else:
            if target.stat().st_size > MAX_IMAGE_SOURCE_BYTES:
                return DerivedResource(413, "application/octet-stream", b"")
            if not HAS_PIL:
                return DerivedResource(501, "application/octet-stream", b"")
            with PilImage.open(target) as image:
                if image.width > MAX_IMAGE_DIMENSION or image.height > MAX_IMAGE_DIMENSION:
                    return DerivedResource(413, "application/octet-stream", b"")
                if image.mode not in ("RGB", "L"):
                    image = image.convert("RGB")
                image.thumbnail((width, height), PilImage.LANCZOS)
                output = BytesIO()
                image.save(output, format="JPEG", quality=75, optimize=True)
                data = output.getvalue()
        if not data or len(data) > MAX_THUMBNAIL_BYTES:
            return DerivedResource(413, "application/octet-stream", b"")
        cache.put(key, data)
        return DerivedResource(200, "image/jpeg", data)


derived_media_service = DerivedMediaService()
