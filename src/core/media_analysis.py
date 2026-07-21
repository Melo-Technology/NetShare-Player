"""Background audio analysis using only FFmpeg and the Python standard library."""

from __future__ import annotations

import array
import json
import math
import queue
import re
import statistics
import subprocess
import threading
from pathlib import Path
from typing import Callable, Iterable

from src.deps import FFMPEG_BIN, HAS_FFMPEG
from src.core.hardware_profile import HardwareProfile

AUDIO_EXTENSIONS = {
    ".mp3", ".flac", ".aac", ".wav", ".ogg", ".opus", ".m4a", ".wma",
    ".aiff", ".aif", ".alac", ".ape", ".mka",
}
TARGET_LUFS = -14.0
WAVEFORM_BINS = 256
PCM_SAMPLE_RATE = 2_000
LONG_WAVEFORM_SAMPLE_RATE = 400
LONG_TRACK_SECONDS = 20 * 60
LONG_CUE_WINDOW_SECONDS = 60
MIN_CROSSFADE_TRACK_SECONDS = 25
DEFAULT_CROSSFADE_SECONDS = 5.0
ANALYSIS_VERSION = 2


def is_audio(path: Path) -> bool:
    return path.suffix.lower() in AUDIO_EXTENSIONS


def _run_ffmpeg(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(FFMPEG_BIN), *args], capture_output=True, timeout=timeout, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _duration(path: Path) -> float | None:
    probe = Path(FFMPEG_BIN).with_name("ffprobe.exe" if Path(FFMPEG_BIN).suffix else "ffprobe")
    if not probe.exists():
        return None
    try:
        result = subprocess.run(
            [str(probe), "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", str(path)],
            capture_output=True, timeout=30, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        value = float(result.stdout.decode("ascii", errors="ignore").strip())
        return value if math.isfinite(value) and value > 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _loudness(path: Path) -> tuple[float | None, float | None]:
    result = _run_ffmpeg([
        "-hide_banner", "-nostdin", "-i", str(path), "-af",
        "loudnorm=I=-14:TP=-1:LRA=11:print_format=json", "-f", "null", "-",
    ], 180)
    text = result.stderr.decode("utf-8", errors="replace")
    blocks = re.findall(r"\{[^{}]*\}", text, flags=re.DOTALL)
    for block in reversed(blocks):
        try:
            measured = float(json.loads(block)["input_i"])
            if math.isfinite(measured):
                return round(measured, 2), round(TARGET_LUFS - measured, 2)
        except (ValueError, KeyError, json.JSONDecodeError):
            continue
    return None, None


def _pcm(path: Path, *, sample_rate: int = PCM_SAMPLE_RATE,
         start: float | None = None, length: float | None = None) -> list[float]:
    args = ["-hide_banner", "-loglevel", "error", "-nostdin"]
    if start is not None:
        args.extend(["-ss", f"{max(0.0, start):.3f}"])
    args.extend(["-i", str(path)])
    if length is not None:
        args.extend(["-t", f"{length:.3f}"])
    args.extend(["-vn", "-ac", "1", "-ar", str(sample_rate), "-f", "f32le", "-"])
    result = _run_ffmpeg(args, 240)
    samples = array.array("f")
    samples.frombytes(result.stdout[:len(result.stdout) - len(result.stdout) % 4])
    return list(samples)


def _normalise_waveform(rms: Iterable[float], peaks: Iterable[float]) -> list[float]:
    rms_values, peak_values = list(rms), list(peaks)
    max_rms, max_peak = max(rms_values, default=0.0) or 1.0, max(peak_values, default=0.0) or 1.0
    return [
        round(min(1.0, 0.7 * (r / max_rms) + 0.3 * (p / max_peak)), 4)
        for r, p in zip(rms_values, peak_values)
    ]


def _waveform(samples: list[float], bins: int = WAVEFORM_BINS) -> list[float]:
    if not samples:
        return []
    rms, peaks = [], []
    for index in range(bins):
        begin = index * len(samples) // bins
        end = (index + 1) * len(samples) // bins
        chunk = samples[begin:end]
        rms.append(math.sqrt(sum(v * v for v in chunk) / len(chunk)) if chunk else 0.0)
        peaks.append(max((abs(v) for v in chunk), default=0.0))
    return _normalise_waveform(rms, peaks)


def _streamed_waveform(path: Path, duration: float, bins: int = WAVEFORM_BINS) -> list[float]:
    command = [str(FFMPEG_BIN), "-hide_banner", "-loglevel", "error", "-nostdin",
               "-i", str(path), "-vn", "-ac", "1", "-ar", str(LONG_WAVEFORM_SAMPLE_RATE),
               "-f", "f32le", "-"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    sums = [0.0] * bins
    counts = [0] * bins
    peaks = [0.0] * bins
    expected = max(1, round(duration * LONG_WAVEFORM_SAMPLE_RATE))
    sample_index = 0
    remainder = b""
    assert process.stdout is not None
    while True:
        block = process.stdout.read(64 * 1024)
        if not block:
            break
        block = remainder + block
        usable = len(block) - len(block) % 4
        values = array.array("f")
        values.frombytes(block[:usable])
        remainder = block[usable:]
        for value in values:
            bucket = min(bins - 1, sample_index * bins // expected)
            sums[bucket] += value * value
            counts[bucket] += 1
            peaks[bucket] = max(peaks[bucket], abs(value))
            sample_index += 1
    process.wait(timeout=30)
    rms = [math.sqrt(total / count) if count else 0.0 for total, count in zip(sums, counts)]
    return _normalise_waveform(rms, peaks)


def _bpm(samples: list[float], sample_rate: int = PCM_SAMPLE_RATE) -> float | None:
    """Estimate tempo from energy-onset autocorrelation; intentionally lightweight."""
    if len(samples) < sample_rate * 8:
        return None
    hop = max(1, sample_rate // 10)
    energy = [sum(abs(v) for v in samples[i:i + hop]) / hop for i in range(0, len(samples), hop)]
    onset = [max(0.0, energy[i] - energy[i - 1]) for i in range(1, len(energy))]
    if not onset or max(onset) <= 0:
        return None
    mean = sum(onset) / len(onset)
    onset = [v - mean for v in onset]
    frame_rate = sample_rate / hop
    best_lag, best_score = None, float("-inf")
    for lag in range(max(1, math.ceil(frame_rate * 60 / 200)),
                     max(1, math.floor(frame_rate * 60 / 60)) + 1):
        score = sum(onset[i] * onset[i - lag] for i in range(lag, len(onset)))
        if score > best_score:
            best_score, best_lag = score, lag
    return round(frame_rate * 60 / best_lag, 1) if best_score > 0 and best_lag else None


def detect_cue_out(samples: list[float], duration: float, *, sample_rate: int = PCM_SAMPLE_RATE,
                   window_start: float = 0.0) -> tuple[float | None, float | None]:
    """Detect a final fade/silence and return (cue-out, suggested crossfade)."""
    if duration < MIN_CROSSFADE_TRACK_SECONDS or not samples:
        return None, None
    frame_size = max(1, sample_rate // 4)
    energies = [math.sqrt(sum(v * v for v in samples[i:i + frame_size]) /
                          max(1, len(samples[i:i + frame_size])))
                for i in range(0, len(samples), frame_size)]
    if len(energies) < 8:
        return None, None
    reference_slice = energies[:max(4, len(energies) * 2 // 3)]
    reference = statistics.median(sorted(reference_slice)[len(reference_slice) // 2:]) or max(energies)
    cue_frame = None
    end_is_low = statistics.mean(energies[-min(4, len(energies)):]) <= reference * 0.15
    # Search the whole final analysis minute. The previous 12-second window
    # could place the cue *inside* a long silent tail, defeating the overlap.
    search_start = max(1, len(energies) - 60 * 4)
    if end_is_low:
        for index in range(search_start, len(energies) - 3):
            tail = energies[index:]
            falling = sum(tail[i] <= tail[i - 1] * 1.12 for i in range(1, len(tail))) / max(1, len(tail) - 1)
            if energies[index] <= reference * 0.92 and energies[index - 1] > reference * 0.92 and falling >= 0.70:
                cue_frame = index
                break
    for index in range(search_start, len(energies) - 3):
        if cue_frame is not None:
            break
        tail = energies[index:]
        low_ratio = sum(value <= reference * 0.18 for value in tail) / len(tail)
        end_is_low = statistics.mean(tail[-min(4, len(tail)):]) <= reference * 0.15
        falling = sum(tail[i] <= tail[i - 1] * 1.12 for i in range(1, len(tail))) / max(1, len(tail) - 1)
        if end_is_low and low_ratio >= 0.55 and falling >= 0.65:
            cue_frame = index
            break
    if cue_frame is None:
        cue = max(0.0, duration - DEFAULT_CROSSFADE_SECONDS)
        return round(cue, 3), DEFAULT_CROSSFADE_SECONDS
    cue = min(duration, window_start + cue_frame * frame_size / sample_rate)
    suggestion = min(12.0, max(2.0, duration - cue))
    return round(cue, 3), round(suggestion, 2)


def _long_bpm(path: Path, duration: float) -> float | None:
    segment_length = min(90.0, duration / 4)
    starts = [0.0, max(0.0, duration / 2 - segment_length / 2), max(0.0, duration - segment_length)]
    estimates = [_bpm(_pcm(path, start=start, length=segment_length)) for start in starts]
    valid = [value for value in estimates if value is not None]
    return round(statistics.median(valid), 1) if valid else None


def analyze_audio(path: Path, bpm_enabled: bool) -> dict:
    if not HAS_FFMPEG or not FFMPEG_BIN:
        return {"analysis_error": "ffmpeg_unavailable"}
    duration = _duration(path)
    integrated_lufs, gain = _loudness(path)
    if duration and duration > LONG_TRACK_SECONDS:
        waveform = _streamed_waveform(path, duration)
        window_start = max(0.0, duration - LONG_CUE_WINDOW_SECONDS)
        cue_samples = _pcm(path, start=window_start, length=LONG_CUE_WINDOW_SECONDS)
        cue, suggestion = detect_cue_out(cue_samples, duration, window_start=window_start)
        bpm = _long_bpm(path, duration) if bpm_enabled else None
    else:
        samples = _pcm(path)
        effective_duration = duration or len(samples) / PCM_SAMPLE_RATE
        waveform = _waveform(samples)
        cue, suggestion = detect_cue_out(samples, effective_duration)
        bpm = _bpm(samples) if bpm_enabled else None
        duration = effective_duration
    return {
        "analysis_version": ANALYSIS_VERSION,
        "integrated_lufs": integrated_lufs,
        "loudness_gain": gain,
        "waveform": waveform,
        "bpm": bpm,
        "duration_seconds": round(duration, 3) if duration else None,
        "cue_out_seconds": cue,
        "suggested_crossfade_seconds": suggestion,
    }


class MediaAnalysisQueue:
    def __init__(self, profile: HardwareProfile, on_result: Callable[[str, dict], None]):
        self.profile = profile
        self.on_result = on_result
        self._queue: queue.PriorityQueue[tuple[int, int, str, Path]] = queue.PriorityQueue()
        self._pending: dict[str, int] = {}
        self._sequence = 0
        self._lock = threading.Lock()
        for number in range(profile.workers):
            threading.Thread(target=self._worker, daemon=True, name=f"media-analysis-{number + 1}").start()

    def submit(self, rel_path: str, path: Path, *, priority: bool = False) -> bool:
        if not is_audio(path):
            return False
        rank = 0 if priority else 10
        with self._lock:
            previous = self._pending.get(rel_path)
            if previous is not None and previous <= rank:
                return False
            self._pending[rel_path] = rank
            self._sequence += 1
            sequence = self._sequence
        self._queue.put_nowait((rank, sequence, rel_path, path))
        return True

    def _worker(self):
        while True:
            item = self._queue.get()
            rank, _, rel_path, path = item
            with self._lock:
                if self._pending.get(rel_path) != rank:
                    self._queue.task_done()
                    continue
            try:
                self.on_result(rel_path, analyze_audio(path, self.profile.bpm_enabled))
            except Exception as exc:
                self.on_result(rel_path, {"analysis_error": str(exc)})
            finally:
                with self._lock:
                    if self._pending.get(rel_path) == rank:
                        self._pending.pop(rel_path, None)
                self._queue.task_done()
