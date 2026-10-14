"""Lazy HLS segment generation and bounded disk caching."""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import src.deps as deps
import src.state as state
from src.core.gpu_encoding import gpu_encoder_arguments

_LOGGER = logging.getLogger(__name__)

SEGMENT_SECONDS = 6
CACHE_TTL_SECONDS = 60 * 60
CACHE_MAX_BYTES = 2 * 1024 * 1024 * 1024
ORPHAN_MAX_AGE_SECONDS = 5 * 60
TRANSCODE_TIMEOUT_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 20
FFMPEG_PROCESS_MEMORY_LIMIT_MIB = 1536
FFMPEG_PROCESS_MEMORY_LIMIT_BYTES = FFMPEG_PROCESS_MEMORY_LIMIT_MIB * 1024 * 1024
MEMORY_WATCH_INTERVAL_SECONDS = 0.05
GIB = 1024 * 1024 * 1024
LOW_RAM_THRESHOLD_BYTES = 4 * GIB
COMFORTABLE_RAM_THRESHOLD_BYTES = 8 * GIB
DEFAULT_GLOBAL_TRANSCODE_LIMIT = 2
DEFAULT_GUEST_TRANSCODE_LIMIT = 1
GPU_TRANSCODE_LIMIT = 1
GPU_CIRCUIT_BREAKER_THRESHOLD = 2
_CACHE_DIR = Path(tempfile.gettempdir()) / "netshare-hls-cache"
_DURATION_RE = re.compile(r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)")
_locks_guard = threading.Lock()
_cache_guard = threading.Lock()
_duration_guard = threading.Lock()
_duration_cache: dict[str, tuple[float, float]] = {}
_gpu_slots = threading.BoundedSemaphore(GPU_TRANSCODE_LIMIT)
_gpu_failures: dict[str, int] = {}
_gpu_disabled: set[str] = set()
_gpu_circuit_guard = threading.Lock()
_unix_memory_limit_probe_guard = threading.Lock()
_unix_memory_limit_available: bool | None = None
_SUBPROCESS_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

VARIANTS = {
    "source": {"height": None, "bandwidth": 6_000_000},
    "720p": {"height": 720, "bandwidth": 2_800_000},
    "480p": {"height": 480, "bandwidth": 1_400_000},
}
_USE_SYSTEM_MEMORY = object()


def variant_descriptors() -> list[dict]:
    """Public, JSON-safe HLS profiles used by Player-side selection."""
    return [
        {"id": name, "height": profile["height"], "bandwidth": profile["bandwidth"]}
        for name, profile in available_variants().items()
    ]


def available_variants(
    total_memory_bytes: int | None | object = _USE_SYSTEM_MEMORY,
) -> dict[str, dict]:
    """Hide the high-memory source profile below the comfortable RAM tier."""
    if total_memory_bytes is _USE_SYSTEM_MEMORY:
        total_memory_bytes = effective_transcode_memory_bytes()
    return _available_variants_for_memory(total_memory_bytes)


def _available_variants_for_memory(total_memory_bytes: int | None) -> dict[str, dict]:
    if total_memory_bytes is not None and total_memory_bytes < COMFORTABLE_RAM_THRESHOLD_BYTES:
        return {name: profile for name, profile in VARIANTS.items() if name != "source"}
    return dict(VARIANTS)


class AdaptiveStreamingError(RuntimeError):
    pass


class TranscodingBusyError(AdaptiveStreamingError):
    pass


class TranscodingTimeoutError(AdaptiveStreamingError):
    pass


class TranscodingMemoryLimitError(AdaptiveStreamingError):
    pass


class GPUTranscodingBusyError(AdaptiveStreamingError):
    pass


def reset_gpu_circuit_breakers() -> None:
    with _gpu_circuit_guard:
        _gpu_failures.clear()
        _gpu_disabled.clear()


def gpu_circuit_breaker_open(backend: str) -> bool:
    with _gpu_circuit_guard:
        return backend in _gpu_disabled


def _record_gpu_result(backend: str, *, success: bool) -> None:
    with _gpu_circuit_guard:
        if success:
            _gpu_failures.pop(backend, None)
            return
        count = _gpu_failures.get(backend, 0) + 1
        _gpu_failures[backend] = count
        if count >= GPU_CIRCUIT_BREAKER_THRESHOLD:
            _gpu_disabled.add(backend)
            state._emit(
                f"HLS  GPU backend {backend} temporarily disabled after {count} failures",
                "error",
            )


def _verified_gpu_backend(preference: str | None = None) -> str | None:
    selected = str(
        state.GPU_ENCODER_PREFERENCE if preference is None else preference
    ).strip().lower()
    if selected == "cpu":
        return None
    states = deps.FFMPEG_CAPABILITIES.gpu_encoders
    if selected in {"nvenc", "qsv", "amf", "videotoolbox"}:
        candidates = (selected,)
    elif selected in {"auto", "gpu"}:
        candidates = ("nvenc", "qsv", "amf", "videotoolbox")
    else:
        return None
    for backend in candidates:
        capability = states.get(backend)
        if capability is not None and capability.verified and not gpu_circuit_breaker_open(backend):
            return backend
    return None


@contextmanager
def _gpu_transcode_slot():
    acquired = _gpu_slots.acquire(blocking=False)
    if not acquired:
        raise GPUTranscodingBusyError("GPU transcoding session limit reached")
    try:
        yield
    finally:
        _gpu_slots.release()


class _NullMemoryLimit:
    def limit_was_hit(self) -> bool:
        return False

    def close(self) -> None:
        pass


def _system_total_memory_bytes() -> int | None:
    if os.name == "nt":
        import ctypes

        class _MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
        return None
    try:
        return int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def transcode_admission_limits(total_memory_bytes: int | None) -> tuple[int, int]:
    """Return global/guest slot counts for the named conservative RAM tiers."""
    if total_memory_bytes is None:
        return DEFAULT_GLOBAL_TRANSCODE_LIMIT, DEFAULT_GUEST_TRANSCODE_LIMIT
    if total_memory_bytes < LOW_RAM_THRESHOLD_BYTES:
        return 1, 0
    if total_memory_bytes < COMFORTABLE_RAM_THRESHOLD_BYTES:
        return 1, 1
    return DEFAULT_GLOBAL_TRANSCODE_LIMIT, DEFAULT_GUEST_TRANSCODE_LIMIT


def automatic_performance_preset(total_memory_bytes: int | None) -> str:
    """Name the existing S6 RAM tier without introducing a second threshold grid."""
    limits = transcode_admission_limits(total_memory_bytes)
    if limits == (1, 0):
        return "economy"
    if total_memory_bytes is not None and total_memory_bytes < COMFORTABLE_RAM_THRESHOLD_BYTES:
        return "balanced_light"
    return "balanced"


def performance_preset_memory_bytes(
    preset: str, detected_memory_bytes: int | None,
) -> int | None:
    """Map a UI preset onto representative inputs for the existing S6 policy."""
    return {
        "economy": LOW_RAM_THRESHOLD_BYTES - 1,
        "balanced_light": LOW_RAM_THRESHOLD_BYTES,
        "balanced": COMFORTABLE_RAM_THRESHOLD_BYTES,
        "performance": COMFORTABLE_RAM_THRESHOLD_BYTES,
    }.get(str(preset or "").strip().lower(), detected_memory_bytes)


def effective_transcode_memory_bytes(
    total_memory_bytes: int | None | object = _USE_SYSTEM_MEMORY,
    preset: str | None = None,
) -> int | None:
    if total_memory_bytes is _USE_SYSTEM_MEMORY:
        total_memory_bytes = SYSTEM_TOTAL_MEMORY_BYTES
    selected = state.PERFORMANCE_PRESET if preset is None else preset
    return performance_preset_memory_bytes(selected, total_memory_bytes)


def performance_policy(
    preset: str, detected_memory_bytes: int | None,
) -> dict[str, object]:
    """Describe a preset exclusively through the existing S6 mechanisms."""
    effective_memory = effective_transcode_memory_bytes(
        detected_memory_bytes, preset,
    )
    global_limit, guest_limit = transcode_admission_limits(effective_memory)
    variants = _available_variants_for_memory(effective_memory)
    return {
        "global_transcode_limit": global_limit,
        "guest_transcode_limit": guest_limit,
        "source_available": "source" in variants,
        "ffmpeg_process_memory_limit_mib": FFMPEG_PROCESS_MEMORY_LIMIT_MIB,
    }


SYSTEM_TOTAL_MEMORY_BYTES = _system_total_memory_bytes()
GLOBAL_TRANSCODE_LIMIT, GUEST_TRANSCODE_LIMIT = transcode_admission_limits(
    effective_transcode_memory_bytes()
)
_global_slots = threading.BoundedSemaphore(GLOBAL_TRANSCODE_LIMIT)
_guest_slots = threading.BoundedSemaphore(GUEST_TRANSCODE_LIMIT)


def configure_performance_preset(preset: str) -> dict[str, object]:
    """Apply a persisted preset to new HLS admissions without weakening hard limits."""
    global GLOBAL_TRANSCODE_LIMIT, GUEST_TRANSCODE_LIMIT
    global _global_slots, _guest_slots
    policy = performance_policy(preset, SYSTEM_TOTAL_MEMORY_BYTES)
    GLOBAL_TRANSCODE_LIMIT = int(policy["global_transcode_limit"])
    GUEST_TRANSCODE_LIMIT = int(policy["guest_transcode_limit"])
    _global_slots = threading.BoundedSemaphore(GLOBAL_TRANSCODE_LIMIT)
    _guest_slots = threading.BoundedSemaphore(GUEST_TRANSCODE_LIMIT)
    return policy


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _WindowsJobMemoryLimit:
        def __init__(self, process, limit_bytes: int):
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.QueryInformationJobObject.argtypes = [
                wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.QueryInformationJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            self._kernel32 = kernel32
            self._limit_bytes = limit_bytes
            self._handle = kernel32.CreateJobObjectW(None, None)
            if not self._handle:
                raise ctypes.WinError(ctypes.get_last_error())
            information = _ExtendedLimitInformation()
            information.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_PROCESS_MEMORY
            information.ProcessMemoryLimit = limit_bytes
            if not kernel32.SetInformationJobObject(
                self._handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(information),
                ctypes.sizeof(information),
            ):
                self.close()
                raise ctypes.WinError(ctypes.get_last_error())
            if not kernel32.AssignProcessToJobObject(
                self._handle, wintypes.HANDLE(process._handle),
            ):
                self.close()
                raise ctypes.WinError(ctypes.get_last_error())

        def limit_was_hit(self) -> bool:
            information = _ExtendedLimitInformation()
            if not self._kernel32.QueryInformationJobObject(
                self._handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(information),
                ctypes.sizeof(information),
                None,
            ):
                return False
            return information.PeakProcessMemoryUsed >= self._limit_bytes

        def close(self) -> None:
            handle, self._handle = getattr(self, "_handle", None), None
            if handle:
                self._kernel32.CloseHandle(handle)


def _set_unix_memory_limit(limit_bytes: int, *, raise_on_failure: bool = False) -> bool:
    try:
        import resource
    except Exception:
        if raise_on_failure:
            raise
        return False

    last_error = None
    attempted_limits = set()
    for limit_name in ("RLIMIT_AS", "RLIMIT_RSS"):
        limit_kind = getattr(resource, limit_name, None)
        if limit_kind is None or limit_kind in attempted_limits:
            continue
        attempted_limits.add(limit_kind)
        try:
            resource.setrlimit(limit_kind, (limit_bytes, limit_bytes))
            return True
        except Exception as error:
            last_error = error

    if raise_on_failure and last_error is not None:
        raise last_error
    if raise_on_failure:
        raise RuntimeError("no supported Unix process memory limit is available")
    return False


def _probe_macos_memory_limit(executable: str) -> bool:
    global _unix_memory_limit_available
    with _unix_memory_limit_probe_guard:
        if _unix_memory_limit_available is not None:
            return _unix_memory_limit_available
        environment = os.environ | {"OBJC_DISABLE_INITIALIZE_FORK_SAFETY": "YES"}
        try:
            process = subprocess.Popen(
                [executable, "-version"],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=_SUBPROCESS_FLAGS,
                env=environment,
                preexec_fn=lambda: _set_unix_memory_limit(
                    FFMPEG_PROCESS_MEMORY_LIMIT_BYTES,
                    raise_on_failure=True,
                ),
            )
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        except Exception as error:
            _unix_memory_limit_available = False
            _LOGGER.warning(
                "FFmpeg memory limit unavailable on this platform; transcoding is "
                "not protected by this per-process safeguard: exception=%r "
                "platform=%s executable=%r",
                error,
                sys.platform,
                executable,
            )
        else:
            _unix_memory_limit_available = True
        return _unix_memory_limit_available


def _memory_limited_popen_kwargs(executable: str | None = None) -> dict:
    if os.name == "nt":
        return {}
    kwargs = {}
    if sys.platform == "darwin":
        kwargs["env"] = os.environ | {"OBJC_DISABLE_INITIALIZE_FORK_SAFETY": "YES"}
        if executable is not None and not _probe_macos_memory_limit(executable):
            return kwargs
    kwargs["preexec_fn"] = lambda: _set_unix_memory_limit(
        FFMPEG_PROCESS_MEMORY_LIMIT_BYTES
    )
    return kwargs


def _apply_process_memory_limit(process):
    if os.name == "nt":
        return _WindowsJobMemoryLimit(process, FFMPEG_PROCESS_MEMORY_LIMIT_BYTES)
    return _NullMemoryLimit()


def _process_rss_bytes(process) -> int | None:
    if os.name == "nt":
        class _ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        if psapi.GetProcessMemoryInfo(
            wintypes.HANDLE(process._handle), ctypes.byref(counters), counters.cb,
        ):
            return int(counters.WorkingSetSize)
        return None
    status = Path(f"/proc/{process.pid}/statm")
    try:
        resident_pages = int(status.read_text(encoding="ascii").split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError, AttributeError):
        return None


def _memory_watchdog(process, stop: threading.Event, exceeded: threading.Event) -> None:
    while not stop.wait(MEMORY_WATCH_INTERVAL_SECONDS):
        rss = _process_rss_bytes(process)
        if rss is not None and rss >= FFMPEG_PROCESS_MEMORY_LIMIT_BYTES:
            exceeded.set()
            try:
                process.kill()
            except OSError:
                pass
            return


@dataclass
class _KeyLock:
    lock: threading.Lock
    users: int = 0


_locks: dict[str, _KeyLock] = {}


@contextmanager
def _key_lock(key: str, timeout: float):
    with _locks_guard:
        entry = _locks.setdefault(key, _KeyLock(threading.Lock()))
        entry.users += 1
    acquired = entry.lock.acquire(timeout=timeout)
    if not acquired:
        with _locks_guard:
            entry.users -= 1
            if entry.users == 0:
                _locks.pop(key, None)
        raise TranscodingBusyError("matching HLS segment is still being generated")
    try:
        yield
    finally:
        entry.lock.release()
        with _locks_guard:
            entry.users -= 1
            if entry.users == 0:
                _locks.pop(key, None)


@contextmanager
def _transcode_slot(*, guest: bool):
    global_slots = _global_slots
    guest_slots = _guest_slots
    guest_acquired = False
    if guest:
        guest_acquired = guest_slots.acquire(blocking=False)
        if not guest_acquired:
            raise TranscodingBusyError("guest transcoding limit reached")
    global_acquired = global_slots.acquire(blocking=False)
    if not global_acquired:
        if guest_acquired:
            guest_slots.release()
        raise TranscodingBusyError("server transcoding limit reached")
    try:
        yield
    finally:
        global_slots.release()
        if guest_acquired:
            guest_slots.release()


def _run_ffmpeg(command: list[str], *, timeout: float) -> tuple[int, bytes]:
    """Run one bounded FFmpeg process without a command shell."""
    popen_kwargs = _memory_limited_popen_kwargs(command[0] if command else None)
    try:
        process = subprocess.Popen(
            command,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=_SUBPROCESS_FLAGS,
            **popen_kwargs,
        )
    except Exception as error:
        _LOGGER.exception(
            "FFmpeg process start failed: exception=%r platform=%s "
            "preexec_fn=%s fork_safety_override=%s executable=%r",
            error,
            sys.platform,
            "preexec_fn" in popen_kwargs,
            popen_kwargs.get("env", {}).get("OBJC_DISABLE_INITIALIZE_FORK_SAFETY"),
            command[0] if command else None,
        )
        raise AdaptiveStreamingError(
            f"ffmpeg start failed ({type(error).__name__}): {error}"
        ) from error
    try:
        memory_limit = _apply_process_memory_limit(process)
    except OSError as error:
        process.kill()
        process.communicate()
        raise AdaptiveStreamingError(f"ffmpeg memory limit setup failed: {error}") from error
    stop_watchdog = threading.Event()
    memory_exceeded = threading.Event()
    watchdog = threading.Thread(
        target=_memory_watchdog,
        args=(process, stop_watchdog, memory_exceeded),
        daemon=True,
        name="netshare-ffmpeg-memory-watchdog",
    )
    watchdog.start()
    timeout_error = None
    try:
        _, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        _, stderr = process.communicate()
        timeout_error = error
    finally:
        stop_watchdog.set()
        watchdog.join(timeout=1)
    limit_was_hit = memory_exceeded.is_set() or memory_limit.limit_was_hit()
    memory_limit.close()
    if limit_was_hit:
        if process.poll() is None:
            process.kill()
            process.communicate()
        state._emit(
            "HLS  FFmpeg process exceeded the "
            f"{FFMPEG_PROCESS_MEMORY_LIMIT_MIB} MiB memory limit and was terminated",
            "error",
        )
        raise TranscodingMemoryLimitError(
            f"ffmpeg exceeded the {FFMPEG_PROCESS_MEMORY_LIMIT_MIB} MiB memory limit"
        )
    if timeout_error is not None:
        raise TranscodingTimeoutError(
            f"ffmpeg exceeded the {int(timeout)} second limit"
        ) from timeout_error
    return process.returncode, stderr or b""


def probe_duration(path: Path, *, guest: bool = False) -> float:
    if not deps.HAS_HLS_TRANSCODING or not deps.FFMPEG_BIN:
        raise AdaptiveStreamingError("ffmpeg unavailable")
    with _transcode_slot(guest=guest):
        duration = _probe_duration_with_ffprobe(path)
        if duration is None:
            _, stderr = _run_ffmpeg(
                [deps.FFMPEG_BIN, "-hide_banner", "-nostdin", "-i", str(path)],
                timeout=PROBE_TIMEOUT_SECONDS,
            )
            match = _DURATION_RE.search(stderr.decode("utf-8", errors="replace"))
            if not match:
                raise AdaptiveStreamingError("media duration unavailable")
            hours, minutes, seconds = match.groups()
            duration = int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    if duration <= 0:
        raise AdaptiveStreamingError("invalid media duration")
    with _duration_guard:
        _duration_cache[_media_key(path)] = (duration, time.time())
        if len(_duration_cache) > 512:
            oldest = min(_duration_cache, key=lambda key: _duration_cache[key][1])
            _duration_cache.pop(oldest, None)
    return duration


def _probe_duration_with_ffprobe(path: Path) -> float | None:
    """Prefer ffprobe's structured duration while retaining the FFmpeg fallback."""
    if not deps.FFPROBE_BIN:
        return None
    try:
        completed = subprocess.run(
            [
                str(deps.FFPROBE_BIN), "-v", "error",
                "-show_entries", "format=duration",
                "-of", "default=noprint_wrappers=1:nokey=1", str(path),
            ],
            capture_output=True,
            check=False,
            timeout=PROBE_TIMEOUT_SECONDS,
            creationflags=_SUBPROCESS_FLAGS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    try:
        duration = float(completed.stdout.decode("utf-8").strip())
    except (UnicodeDecodeError, ValueError):
        return None
    return duration if math.isfinite(duration) and duration > 0 else None


def segment_count(duration: float) -> int:
    return max(1, math.ceil(duration / SEGMENT_SECONDS))


def _media_key(path: Path) -> str:
    stat = path.stat()
    value = f"{path.resolve()}\0{stat.st_size}\0{stat.st_mtime_ns}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def cached_segment_count(path: Path) -> int | None:
    key = _media_key(path)
    with _duration_guard:
        cached = _duration_cache.get(key)
        if cached is None:
            return None
        duration, recorded_at = cached
        if time.time() - recorded_at > CACHE_TTL_SECONDS:
            _duration_cache.pop(key, None)
            return None
    return segment_count(duration)


def _cache_key(path: Path, variant: str, index: int) -> str:
    stat = path.stat()
    value = f"{path.resolve()}\0{stat.st_size}\0{stat.st_mtime_ns}\0{variant}\0{index}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()



def clear_adaptive_streaming_cache() -> dict[str, int]:
    """Clear generated HLS files and duration metadata when no transcode is active.

    A cache reset is an administrative operation.  Refusing to run while a
    per-media generation lock exists prevents deleting a segment underneath an
    in-flight FFmpeg process.
    """
    with _locks_guard:
        active_generations = sum(entry.users for entry in _locks.values())
    if active_generations:
        raise TranscodingBusyError("HLS transcoding is active")

    removed_files = 0
    removed_bytes = 0
    with _cache_guard:
        try:
            entries = list(_CACHE_DIR.iterdir()) if _CACHE_DIR.exists() else []
        except OSError:
            entries = []
        for path in entries:
            if not path.is_file():
                continue
            try:
                size = int(path.stat().st_size)
                path.unlink(missing_ok=True)
                removed_files += 1
                removed_bytes += size
            except OSError:
                continue
        try:
            _CACHE_DIR.rmdir()
        except OSError:
            pass
    with _duration_guard:
        duration_entries = len(_duration_cache)
        _duration_cache.clear()
    return {
        "files": removed_files,
        "bytes": removed_bytes,
        "duration_entries": duration_entries,
    }

def _ensure_cache_dir() -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            _CACHE_DIR.chmod(0o700)
        except OSError:
            pass


def _cache_entries(pattern: str) -> list[Path]:
    try:
        return [entry for entry in _CACHE_DIR.glob(pattern) if entry.is_file()]
    except OSError:
        return []


def _evict_expired(now: float) -> None:
    try:
        _ensure_cache_dir()
        for entry in _cache_entries("*.ts"):
            try:
                if now - entry.stat().st_mtime > CACHE_TTL_SECONDS:
                    entry.unlink()
            except OSError:
                continue
        for entry in _cache_entries("*.tmp"):
            try:
                if now - entry.stat().st_mtime > ORPHAN_MAX_AGE_SECONDS:
                    entry.unlink()
            except OSError:
                continue
    except OSError:
        pass


def _reserve_cache_space(required: int) -> None:
    if required <= 0 or required > CACHE_MAX_BYTES:
        raise AdaptiveStreamingError("HLS segment exceeds the cache quota")
    entries = []
    total = 0
    for entry in _cache_entries("*.ts"):
        try:
            stat = entry.stat()
        except OSError:
            continue
        entries.append((stat.st_mtime, stat.st_size, entry))
        total += stat.st_size
    for _, size, entry in sorted(entries):
        if total + required <= CACHE_MAX_BYTES:
            break
        try:
            entry.unlink()
            total -= size
        except OSError:
            continue
    if total + required > CACHE_MAX_BYTES:
        raise AdaptiveStreamingError("HLS cache quota exhausted")


def _encoder_arguments(encoder: str, bandwidth: int, backend: str | None) -> list[str]:
    if backend is not None:
        return gpu_encoder_arguments(encoder, bandwidth, backend)
    available_cpus = os.cpu_count() or 2
    cpu_threads = max(1, min(4, (available_cpus + 1) // 2))
    arguments = ["-threads", str(cpu_threads), "-c:v", encoder]
    if encoder == "libx264":
        arguments += ["-preset", "veryfast", "-profile:v", "high"]
    return [*arguments, "-pix_fmt", "yuv420p", "-b:v", str(bandwidth)]


def _segment_command(
    path: Path,
    profile: dict,
    index: int,
    temporary: Path,
    backend: str | None,
    include_audio: bool = True,
) -> list[str]:
    command = [
        str(deps.FFMPEG_BIN), "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
        "-ss", str(index * SEGMENT_SECONDS), "-i", str(path),
        "-t", str(SEGMENT_SECONDS), "-map", "0:v:0",
    ]
    if include_audio:
        command += ["-map", "0:a:0?"]
    height = profile["height"]
    if height is not None:
        command += ["-vf", f"scale=-2:'min({height},ih)'" ]
    encoder = (
        deps.FFMPEG_CAPABILITIES.gpu_encoders[backend].encoder
        if backend is not None
        else str(deps.HLS_VIDEO_ENCODER)
    )
    command += _encoder_arguments(encoder, int(profile["bandwidth"]), backend)
    command += ["-force_key_frames", "expr:gte(t,n_forced*6)"]
    if include_audio:
        command += ["-c:a", "aac", "-b:a", "128k", "-ac", "2"]
    else:
        command += ["-an"]
    command += [
        "-output_ts_offset", str(index * SEGMENT_SECONDS),
        "-f", "mpegts", str(temporary),
    ]
    return command


def _audio_segment_command(path: Path, stream_index: int, index: int, temporary: Path) -> list[str]:
    return [
        str(deps.FFMPEG_BIN), "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
        "-ss", str(index * SEGMENT_SECONDS), "-i", str(path),
        "-t", str(SEGMENT_SECONDS), "-map", f"0:{stream_index}",
        "-vn", "-c:a", "aac", "-b:a", "128k", "-ac", "2",
        "-output_ts_offset", str(index * SEGMENT_SECONDS),
        "-f", "mpegts", str(temporary),
    ]


def get_or_create_audio_segment(
    path: Path, stream_index: int, index: int, *, guest: bool = False,
) -> Path:
    if stream_index < 0 or index < 0 or not deps.HAS_HLS_TRANSCODING or not deps.FFMPEG_BIN:
        raise AdaptiveStreamingError("invalid HLS audio segment")
    now = time.time()
    with _cache_guard:
        _evict_expired(now)
    key = _cache_key(path, f"audio-{stream_index}", index)
    output = _CACHE_DIR / f"{key}.ts"
    if output.exists() and now - output.stat().st_mtime <= CACHE_TTL_SECONDS:
        output.touch()
        return output
    with _key_lock(key, TRANSCODE_TIMEOUT_SECONDS + 5):
        if output.exists() and time.time() - output.stat().st_mtime <= CACHE_TTL_SECONDS:
            output.touch()
            return output
        _ensure_cache_dir()
        temporary = _CACHE_DIR / f"{key}.{uuid.uuid4().hex}.tmp"
        try:
            with _transcode_slot(guest=guest):
                returncode, stderr = _run_ffmpeg(
                    _audio_segment_command(path, stream_index, index, temporary),
                    timeout=TRANSCODE_TIMEOUT_SECONDS,
                )
            if returncode != 0 or not temporary.exists() or temporary.stat().st_size <= 0:
                message = stderr.decode("utf-8", errors="replace")[-500:]
                raise AdaptiveStreamingError(message or "audio segment generation failed")
            with _cache_guard:
                _evict_expired(time.time())
                _reserve_cache_space(temporary.stat().st_size)
                temporary.replace(output)
            return output
        finally:
            temporary.unlink(missing_ok=True)


def _run_segment_attempt(command: list[str], backend: str | None) -> tuple[int, bytes]:
    if backend is None:
        return _run_ffmpeg(command, timeout=TRANSCODE_TIMEOUT_SECONDS)
    with _gpu_transcode_slot():
        return _run_ffmpeg(command, timeout=TRANSCODE_TIMEOUT_SECONDS)


def get_or_create_segment(
    path: Path, variant: str, index: int, *, guest: bool = False,
    include_audio: bool = True,
) -> Path:
    if variant not in available_variants() or index < 0:
        raise AdaptiveStreamingError("invalid HLS segment")
    if not deps.HAS_HLS_TRANSCODING or not deps.FFMPEG_BIN or not deps.HLS_VIDEO_ENCODER:
        raise AdaptiveStreamingError("ffmpeg unavailable")
    now = time.time()
    with _cache_guard:
        _evict_expired(now)
    cache_variant = variant if include_audio else f"{variant}-video-only"
    key = _cache_key(path, cache_variant, index)
    output = _CACHE_DIR / f"{key}.ts"
    if output.exists() and now - output.stat().st_mtime <= CACHE_TTL_SECONDS:
        output.touch()
        return output
    with _key_lock(key, TRANSCODE_TIMEOUT_SECONDS + 5):
        if output.exists() and time.time() - output.stat().st_mtime <= CACHE_TTL_SECONDS:
            output.touch()
            return output
        _ensure_cache_dir()
        temporary = _CACHE_DIR / f"{key}.{uuid.uuid4().hex}.tmp"
        profile = VARIANTS[variant]
        gpu_backend = _verified_gpu_backend()
        attempts = (gpu_backend, None) if gpu_backend is not None else (None,)
        try:
            with _transcode_slot(guest=guest):
                for attempt_backend in attempts:
                    temporary.unlink(missing_ok=True)
                    command = _segment_command(
                        path, profile, index, temporary, attempt_backend, include_audio,
                    )
                    try:
                        returncode, stderr = _run_segment_attempt(command, attempt_backend)
                    except GPUTranscodingBusyError as error:
                        if attempt_backend is None:
                            raise
                        state._emit(f"HLS  {error}; retrying once on CPU", "error")
                        continue
                    except AdaptiveStreamingError as error:
                        if attempt_backend is None:
                            raise
                        _record_gpu_result(attempt_backend, success=False)
                        state._emit(
                            f"HLS  GPU backend {attempt_backend} failed: {error}; "
                            "retrying once on CPU",
                            "error",
                        )
                        continue
                    valid_output = (
                        returncode == 0
                        and temporary.exists()
                        and temporary.stat().st_size > 0
                    )
                    if valid_output:
                        if attempt_backend is not None:
                            _record_gpu_result(attempt_backend, success=True)
                        break
                    message = stderr.decode("utf-8", errors="replace")[-500:]
                    if attempt_backend is None:
                        raise AdaptiveStreamingError(
                            message or "ffmpeg segment generation failed"
                        )
                    _record_gpu_result(attempt_backend, success=False)
                    state._emit(
                        f"HLS  GPU backend {attempt_backend} failed: "
                        f"{message or 'segment generation failed'}; retrying once on CPU",
                        "error",
                    )
                else:
                    raise AdaptiveStreamingError("ffmpeg segment generation failed")
            with _cache_guard:
                _evict_expired(time.time())
                _reserve_cache_space(temporary.stat().st_size)
                temporary.replace(output)
            return output
        finally:
            temporary.unlink(missing_ok=True)
