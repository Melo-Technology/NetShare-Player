"""Runtime feature detection for optional dependencies used by the server."""

from __future__ import annotations

import os as _os
import re as _re
import shutil as _shutil
import subprocess as _subprocess
import sys as _sys
import time as _time
from dataclasses import dataclass as _dataclass
from dataclasses import field as _field
from pathlib import Path as _Path

import src.state as _state
from src.core.gpu_encoding import gpu_encoder_arguments as _gpu_encoder_arguments

try:
    import qrcode          # noqa: F401
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    import websockets       # noqa: F401
    import websockets.server  # noqa: F401
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    from watchdog.observers import Observer           # noqa: F401
    from watchdog.events import FileSystemEventHandler  # noqa: F401
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    from PIL import Image as PilImage  # noqa: F401
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

def _resolve_ffmpeg(*, which=_shutil.which) -> str | None:
    """Resolve FFmpeg strictly from the host system PATH."""
    return which("ffmpeg") or which("ffmpeg.exe")


def _resolve_ffprobe(*, which=_shutil.which) -> str | None:
    """Resolve ffprobe independently instead of assuming FFmpeg's directory."""
    return which("ffprobe") or which("ffprobe.exe")


DEBUG_FORCE_NO_FFMPEG_ENV = "NETSHARE_DEBUG_FORCE_NO_FFMPEG"


def _apply_ffmpeg_debug_override(
    ffmpeg: str | None,
    ffprobe: str | None,
    *,
    environ=_os.environ,
) -> tuple[str | None, str | None, bool]:
    """Temporarily hide both tools when explicit manual testing requests it."""
    raw_value = str(environ.get(DEBUG_FORCE_NO_FFMPEG_ENV, "")).strip().lower()
    enabled = raw_value in {"1", "true", "yes", "on"}
    return (None, None, True) if enabled else (ffmpeg, ffprobe, False)


_CPU_H264_ENCODERS = (
    "libx264",
    "libopenh264",
)

_GPU_H264_ENCODERS = {
    "nvenc": "h264_nvenc",
    "qsv": "h264_qsv",
    "amf": "h264_amf",
    "videotoolbox": "h264_videotoolbox",
}


@_dataclass(frozen=True)
class GPUEncoderCapability:
    backend: str
    encoder: str
    declared: bool = False
    verified: bool = False
    failure_reason: str | None = None
    device_name: str | None = None


@_dataclass(frozen=True)
class FFmpegCapabilities:
    available: bool = False
    encoders: frozenset[str] = frozenset()
    muxers: frozenset[str] = frozenset()
    filters: frozenset[str] = frozenset()
    h264_encoder: str | None = None
    hls_transcoding: bool = False
    gpu_encoders: dict[str, GPUEncoderCapability] = _field(default_factory=dict)
    hls_transcoding_gpu: bool = False
    audio_analysis: bool = False
    video_thumbnails: bool = False
    error: str | None = None


_GPU_PROBE_CACHE: dict[str, dict[str, GPUEncoderCapability]] = {}


def _gpu_backend_supported_on_platform(backend: str) -> bool:
    if backend == "videotoolbox":
        return _sys.platform == "darwin"
    if backend == "amf":
        return _sys.platform == "win32"
    return _sys.platform.startswith(("win", "linux"))


_GPU_PROBE_TIMEOUT_SECONDS = 8
_GPU_PROBE_PIXEL_FORMATS = ("yuv420p", "yuv420p10le")


def _gpu_probe_command(executable: str, backend: str, pixel_format: str) -> list[str]:
    # Exercise decoded 1080p frames, including HEVC Main10's common output.
    # Do not force the encoder to nv12: HLS also negotiates its output format.
    return [
        str(executable), "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
        "-f", "lavfi", "-i",
        f"testsrc2=size=1920x1080:rate=30:duration=0.1,format={pixel_format}",
        "-frames:v", "3", "-map", "0:v:0",
        "-vf", "scale=-2:'min(720,ih)'",
        *_gpu_encoder_arguments(_GPU_H264_ENCODERS[backend], 2_800_000, backend),
        "-force_key_frames", "expr:gte(t,n_forced*6)", "-an",
        "-reset_timestamps", "1", "-avoid_negative_ts", "make_zero",
        "-f", "mpegts", "-",
    ]


def _probe_gpu_encoder(executable: str, backend: str, *, runner) -> GPUEncoderCapability:
    encoder = _GPU_H264_ENCODERS[backend]
    deadline = _time.monotonic() + _GPU_PROBE_TIMEOUT_SECONDS
    # The capability is global, not per source: both common bit depths must
    # work. Stop at the first failure and share the previous 8-second budget.
    for pixel_format in _GPU_PROBE_PIXEL_FORMATS:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            return GPUEncoderCapability(
                backend, encoder, declared=True, failure_reason=f"{pixel_format}: probe_timeout",
            )
        try:
            result = runner(
                _gpu_probe_command(executable, backend, pixel_format),
                capture_output=True, timeout=remaining, check=False,
                creationflags=getattr(_subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, _subprocess.SubprocessError) as error:
            return GPUEncoderCapability(
                backend, encoder, declared=True,
                failure_reason=f"{pixel_format}: {type(error).__name__}",
            )
        if result.returncode != 0 or not result.stdout:
            stderr = (result.stderr or b"").decode("utf-8", errors="replace").strip()
            reason = stderr[:450] or (
                f"ffmpeg_exit_{result.returncode}" if result.returncode else "empty_output"
            )
            return GPUEncoderCapability(
                backend, encoder, declared=True, failure_reason=f"{pixel_format}: {reason}",
            )
    return GPUEncoderCapability(backend, encoder, declared=True, verified=True)


def _detect_gpu_encoders(
    executable: str,
    encoders: frozenset[str],
    *,
    runner,
    force_probe: bool = False,
) -> dict[str, GPUEncoderCapability]:
    cache_key = _os.path.normcase(_os.path.abspath(str(executable)))
    cached = None if force_probe else _GPU_PROBE_CACHE.get(cache_key)
    states: dict[str, GPUEncoderCapability] = {}
    for backend, encoder in _GPU_H264_ENCODERS.items():
        declared = encoder in encoders
        if not declared:
            states[backend] = GPUEncoderCapability(backend, encoder)
        elif not _gpu_backend_supported_on_platform(backend):
            states[backend] = GPUEncoderCapability(
                backend, encoder, declared=True, failure_reason="unsupported_platform",
            )
        elif cached is not None and backend in cached:
            states[backend] = cached[backend]
        else:
            states[backend] = _probe_gpu_encoder(executable, backend, runner=runner)
    _GPU_PROBE_CACHE.clear()
    _GPU_PROBE_CACHE[cache_key] = states
    return states


def _listed_components(output: str, flag_pattern: str) -> frozenset[str]:
    components = set()
    matcher = _re.compile(flag_pattern)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and matcher.fullmatch(fields[0]):
            components.update(fields[1].split(","))
    return frozenset(components)


def _detect_ffmpeg_capabilities(
    executable: str | None,
    *,
    runner=_subprocess.run,
    force_gpu_probe: bool = False,
) -> FFmpegCapabilities:
    if not executable:
        return FFmpegCapabilities(error="ffmpeg_not_found")

    try:
        version = runner(
            [str(executable), "-hide_banner", "-version"],
            capture_output=True,
            timeout=10,
            check=False,
            creationflags=getattr(_subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, _subprocess.SubprocessError):
        return FFmpegCapabilities(error="ffmpeg_version_probe_failed")
    if version.returncode != 0:
        return FFmpegCapabilities(error="ffmpeg_version_probe_failed")

    outputs: dict[str, str] = {}
    for inventory in ("encoders", "muxers", "filters"):
        try:
            result = runner(
                [str(executable), "-hide_banner", f"-{inventory}"],
                capture_output=True,
                timeout=10,
                check=False,
                creationflags=getattr(_subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, _subprocess.SubprocessError):
            return FFmpegCapabilities(error=f"ffmpeg_{inventory}_probe_failed")
        if result.returncode != 0:
            return FFmpegCapabilities(error=f"ffmpeg_{inventory}_probe_failed")
        outputs[inventory] = (
            result.stdout + result.stderr
        ).decode("utf-8", errors="replace")

    encoders = _listed_components(outputs["encoders"], r"[A-Z\.]{6}")
    muxers = _listed_components(outputs["muxers"], r"[D\.]*E[D\.]*")
    filters = _listed_components(outputs["filters"], r"[A-Z\|\.]{2,4}")
    h264_encoder = next(
        (name for name in _CPU_H264_ENCODERS if name in encoders),
        None,
    )
    gpu_encoders = _detect_gpu_encoders(
        str(executable), encoders, runner=runner, force_probe=force_gpu_probe,
    )
    return FFmpegCapabilities(
        available=True,
        encoders=encoders,
        muxers=muxers,
        filters=filters,
        h264_encoder=h264_encoder,
        hls_transcoding=bool(h264_encoder and "aac" in encoders and "mpegts" in muxers),
        gpu_encoders=gpu_encoders,
        hls_transcoding_gpu=bool(
            "aac" in encoders
            and "mpegts" in muxers
            and any(state.verified for state in gpu_encoders.values())
        ),
        audio_analysis="loudnorm" in filters,
        video_thumbnails=(
            "mjpeg" in encoders and "image2" in muxers and "scale" in filters
        ),
    )


FFMPEG_BIN: str | None = None
FFPROBE_BIN: str | None = None
FFMPEG_CAPABILITIES = FFmpegCapabilities(error="ffmpeg_not_found")
HAS_FFMPEG = False
HAS_HLS_TRANSCODING = False
HAS_AUDIO_ANALYSIS = False
HAS_VIDEO_THUMBNAILS = False
HLS_VIDEO_ENCODER: str | None = None
FFMPEG_MANUAL_PATH_INVALID = False
FFMPEG_MANUAL_PATH_ERROR: str | None = None
FFMPEG_SOURCE = "none"
DEBUG_FORCE_NO_FFMPEG = False


def refresh_ffmpeg_capabilities(
    manual_path: str | None = None,
    *,
    which=_shutil.which,
    runner=_subprocess.run,
    is_file=lambda path: _Path(path).is_file(),
    is_executable=_os.access,
    environ=_os.environ,
    force_gpu_probe: bool = False,
) -> FFmpegCapabilities:
    """Re-evaluate a manual FFmpeg path, then fall back to the system PATH."""
    global FFMPEG_BIN, FFPROBE_BIN, FFMPEG_CAPABILITIES
    global HAS_FFMPEG, HAS_HLS_TRANSCODING, HAS_AUDIO_ANALYSIS
    global HAS_VIDEO_THUMBNAILS, HLS_VIDEO_ENCODER
    global FFMPEG_MANUAL_PATH_INVALID, FFMPEG_MANUAL_PATH_ERROR, FFMPEG_SOURCE
    global DEBUG_FORCE_NO_FFMPEG

    previous_executable = FFMPEG_BIN
    configured = str(
        _state.FFMPEG_PATH if manual_path is None else manual_path
    ).strip()
    selected = None
    capabilities = None
    manual_error = None
    if configured:
        if not is_file(configured) or not is_executable(configured, _os.X_OK):
            manual_error = "ffmpeg_manual_path_not_executable"
        else:
            candidate = _detect_ffmpeg_capabilities(
                configured, runner=runner, force_gpu_probe=force_gpu_probe,
            )
            if candidate.available:
                selected, capabilities = configured, candidate
            else:
                manual_error = candidate.error or "ffmpeg_manual_path_invalid"

    if selected is None:
        selected = _resolve_ffmpeg(which=which)
        capabilities = _detect_ffmpeg_capabilities(
            selected, runner=runner, force_gpu_probe=force_gpu_probe,
        )
        source = "path" if selected else "none"
    else:
        source = "manual"

    ffprobe = _resolve_ffprobe(which=which)
    selected, ffprobe, debug_override = _apply_ffmpeg_debug_override(
        selected, ffprobe, environ=environ,
    )
    if debug_override:
        capabilities = FFmpegCapabilities(error="ffmpeg_not_found")
        source = "debug"
    DEBUG_FORCE_NO_FFMPEG = debug_override

    FFMPEG_BIN = selected
    FFPROBE_BIN = ffprobe
    FFMPEG_CAPABILITIES = capabilities
    HAS_FFMPEG = capabilities.available
    HAS_HLS_TRANSCODING = capabilities.hls_transcoding
    HAS_AUDIO_ANALYSIS = capabilities.audio_analysis
    HAS_VIDEO_THUMBNAILS = capabilities.video_thumbnails
    HLS_VIDEO_ENCODER = capabilities.h264_encoder
    FFMPEG_MANUAL_PATH_INVALID = bool(manual_error)
    FFMPEG_MANUAL_PATH_ERROR = manual_error
    FFMPEG_SOURCE = source
    if force_gpu_probe or previous_executable != selected:
        streaming = _sys.modules.get("src.core.adaptive_streaming")
        reset_breakers = getattr(streaming, "reset_gpu_circuit_breakers", None)
        if callable(reset_breakers):
            reset_breakers()
    return capabilities


refresh_ffmpeg_capabilities()

try:
    import firebase_admin                           # noqa: F401
    from firebase_admin import credentials          # noqa: F401
    from firebase_admin import remote_config        # noqa: F401
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False

try:
    import requests  # noqa: F401
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from cryptography.fernet import Fernet  # noqa: F401
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import zeroconf  # noqa: F401
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False

MEGATOOLS_BIN: str | None = _shutil.which("megatools") or _shutil.which("megatools.exe")
HAS_MEGATOOLS: bool = MEGATOOLS_BIN is not None
MEGATOOLS_DOWNLOAD_URL = "https://megatools.megous.com/"
