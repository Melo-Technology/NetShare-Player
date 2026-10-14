
"""
File indexing and directory watching for NetShare Server.

The FileIndex class builds an in-memory searchable catalogue of the shared
directory and persists it as a gzip cache. When watchdog is available, the
module-level watcher keeps that index synchronized with filesystem changes.
"""

import gzip
import json
import os
import threading
import time as _time
from collections import OrderedDict
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import src.state as state
from src.core.vault_storage import read_bytes, write_bytes
from src.deps import HAS_WATCHDOG
from src.core.hardware_profile import HARDWARE_PROFILE
from src.core.performance_resources import analysis_queue_limit, effective_worker_budget
from src.core.media_analysis import ANALYSIS_VERSION, MediaAnalysisQueue, is_audio
from src.core.shared_roots import PRIMARY_ROOT_SLOT
from src.core.shared_paths import public_shared_path
from src.core.hidden_folders import is_hidden_folder, is_inside_hidden_folder
from src.core.content_policy import is_config_hidden

if HAS_WATCHDOG:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler as _WatchdogBase
else:
    _WatchdogBase = object   # dummy base so the class still parses

_dir_observer = None
_watch_event_coalescer = None


def _watch_path_is_internal_or_hidden(root: Path, abs_path: str | os.PathLike | None) -> bool:
    """Return True for paths the index intentionally never exposes.

    This check runs before watchdog events enter the coalescer.  In particular,
    NetShare's own atomic cache write (.netshare_index.tmp ->
    .netshare_index.cache) must never feed the WATCH pipeline; on macOS FSEvents
    those self-events can otherwise contribute to an avoidable event storm.
    """
    if not abs_path:
        return True
    try:
        relative = Path(abs_path).relative_to(root)
    except (TypeError, ValueError):
        return False
    parts = relative.parts
    if not parts:
        return False
    # The scanner excludes dot files/folders, so the live watcher must use the
    # same contract.  This covers cache/tmp, .DS_Store, marker files, etc.
    if any(part.startswith(".") for part in parts):
        return True
    return False


class WatchEventCoalescer:
    """Bound and coalesce watchdog callbacks before touching FileIndex."""

    def __init__(
        self, *, debounce_seconds: float, batch_limit: int, capacity: int,
        on_overflow,
    ):
        self.debounce_seconds = max(0.01, float(debounce_seconds))
        self.batch_limit = max(1, int(batch_limit))
        self.capacity = max(self.batch_limit, int(capacity))
        self.on_overflow = on_overflow
        self._events = OrderedDict()
        self._lock = threading.Lock()
        self._overflowed = False
        self._stop = threading.Event()
        self._thread = None

    @property
    def rescan_required(self) -> bool:
        with self._lock:
            return self._overflowed

    def submit(self, key, callback, *, now: float | None = None) -> bool:
        recorded_at = _time.monotonic() if now is None else float(now)
        with self._lock:
            if key in self._events:
                self._events[key] = (recorded_at, callback)
                self._events.move_to_end(key)
                return True
            if len(self._events) >= self.capacity:
                self._overflowed = True
                return False
            self._events[key] = (recorded_at, callback)
            return True

    def configure_limits(self, *, batch_limit: int, capacity: int) -> None:
        """Apply preset limits atomically; overflow becomes an explicit rescan."""
        new_batch = max(1, int(batch_limit))
        new_capacity = max(new_batch, int(capacity))
        with self._lock:
            self.batch_limit = new_batch
            self.capacity = new_capacity
            if len(self._events) > self.capacity:
                self._overflowed = True

    def drain(self, *, now: float | None = None) -> int:
        current = _time.monotonic() if now is None else float(now)
        callbacks = []
        overflowed = False
        with self._lock:
            if self._overflowed:
                overflowed = True
                self._overflowed = False
                self._events.clear()
            else:
                for key, (recorded_at, callback) in list(self._events.items()):
                    if len(callbacks) >= self.batch_limit:
                        break
                    if current - recorded_at < self.debounce_seconds:
                        continue
                    callbacks.append(callback)
                    self._events.pop(key, None)
        if overflowed:
            self.on_overflow()
            return 0
        for callback in callbacks:
            callback()
        return len(callbacks)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop():
            while not self._stop.wait(min(0.05, self.debounce_seconds)):
                self.drain()

        self._thread = threading.Thread(
            target=loop, daemon=True, name="watch-event-coalescer",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None


def _watcher_overflow_rescan():
    state._emit(
        "WATCH  event buffer overflow - rescan required; rebuilding index",
        "error",
    )
    _file_index.build_all(state.SHARED_ROOTS)


def _new_watch_event_coalescer():
    from src.core.performance_resources import logical_cpu_count, watcher_limits

    preset = state.PERFORMANCE_PRESET or "balanced"
    batch, capacity = watcher_limits(preset, logical_cpu_count())
    return WatchEventCoalescer(
        debounce_seconds=0.15,
        batch_limit=batch,
        capacity=capacity,
        on_overflow=_watcher_overflow_rescan,
    )


def configure_watcher_performance(preset: str) -> None:
    """Update the active watcher at a lock-protected batch boundary."""
    if _watch_event_coalescer is None:
        return
    from src.core.performance_resources import logical_cpu_count, watcher_limits

    batch, capacity = watcher_limits(preset, logical_cpu_count())
    _watch_event_coalescer.configure_limits(
        batch_limit=batch, capacity=capacity,
    )


# FileIndex

class FileIndex:
    CACHE_FILENAME = ".netshare_index.cache"

    _TYPE_EXTENSIONS = {
        "image":    {"jpg","jpeg","png","gif","webp","bmp","tiff","tif","svg",
                     "heic","heif","avif","raw","cr2","nef","arw"},
        "video":    {"mp4","mkv","avi","mov","wmv","flv","webm","m4v","mpg",
                     "mpeg","3gp","ts","mts","m2ts","vob","ogv","rm","rmvb"},
        "audio":    {"mp3","flac","aac","wav","ogg","opus","m4a","wma","aiff",
                     "aif","alac","ape","mka","mid","midi"},
        "document": {"pdf","doc","docx","xls","xlsx","ppt","pptx","odt","ods",
                     "odp","txt","rtf","csv","md","epub","mobi","azw","djvu",
                     "pages","numbers","key"},
        "archive":  {"zip","rar","7z","tar","gz","bz2","xz","zst","cab","iso",
                     "dmg","pkg","deb","rpm"},
    }

    # Constructor

    def __init__(self):
        self._lock         = threading.RLock()
        self._entries:  list = []
        self._names_lc: list = []
        self.ready         = False
        self.total         = 0
        self._built_at     = 0.0
        self._dirty        = False
        self._flush_thread: threading.Thread | None = None
        self._flush_stop   = threading.Event()
        self._build_cancel = threading.Event()
        # Live filesystem events that arrive while a full rebuild is assembling
        # a replacement catalogue are buffered and replayed after the atomic
        # catalogue swap.  Without this gate a WATCH add/remove can mutate the
        # old catalogue and then be lost when the scanner replaces _entries.
        self._build_event_gate = threading.RLock()
        self._build_event_active = False
        self._build_event_token: threading.Event | None = None
        self._build_event_queue: list[callable] = []
        self._build_event_overflow = False
        self._build_event_limit = 8192
        self._build_event_replay = threading.local()
        self._paused       = False
        self.profile       = HARDWARE_PROFILE
        self._analysis_lock = threading.Lock()
        self._pending_analysis_budget = None
        self._analysis = self._new_analysis_queue(self.profile.analysis_workers)

    def _current_worker_budget(self):
        preset = state.PERFORMANCE_PRESET or (
            "balanced" if self.profile.name == "standard" else "economy"
        )
        return effective_worker_budget(
            preset,
            self.profile.cpu_count,
            state.INDEX_WORKERS,
            state.ANALYSIS_WORKERS,
        )

    def _new_analysis_queue(self, workers: int, *, suspended: bool = False):
        preset = state.PERFORMANCE_PRESET or (
            "balanced" if self.profile.name == "standard" else "economy"
        )
        profile = replace(self.profile, analysis_workers=workers)
        return MediaAnalysisQueue(
            profile,
            self._store_analysis,
            max_queue=analysis_queue_limit(preset, self.profile.cpu_count),
            start_suspended=suspended,
        )

    def _submit_analysis(self, rel_path: str, path: Path, *, priority: bool = False) -> bool:
        with self._analysis_lock:
            analysis = self._analysis
        return analysis.submit(rel_path, path, priority=priority)

    def configure_worker_budget(self, budget) -> None:
        """Index applies next scan; analysis swaps only while the index is ready."""
        with self._lock:
            if not self.ready:
                self._pending_analysis_budget = budget
                return
        self._replace_analysis_queue(budget.analysis_workers)

    def _replace_analysis_queue(self, workers: int) -> None:
        replacement = self._new_analysis_queue(workers, suspended=True)
        with self._analysis_lock:
            previous = self._analysis
            self._analysis = replacement

        def drain_previous():
            previous.resume_background()
            previous.join()
            previous.shutdown()
            replacement.resume_background()

        threading.Thread(
            target=drain_previous,
            daemon=True,
            name="media-analysis-reconfigure",
        ).start()

    def _finish_build_resource_transition(self) -> None:
        with self._lock:
            pending = self._pending_analysis_budget
            self._pending_analysis_budget = None
        if pending is not None:
            self._replace_analysis_queue(pending.analysis_workers)
        else:
            with self._analysis_lock:
                self._analysis.resume_background()

    # Cache paths

    @staticmethod
    def _cache_path(root) -> Path:
        return Path(root) / FileIndex.CACHE_FILENAME

    # Public API

    def build(self, root, root_slot: str = PRIMARY_ROOT_SLOT):
        """Start rebuilding the index from the filesystem in the background."""
        cancel = self._begin_build()
        if cancel is None:
            return False
        self.ready = False
        with self._analysis_lock:
            self._analysis.suspend_background()
        threading.Thread(
            target=self._build_thread, args=(Path(root), root_slot, cancel), daemon=True
        ).start()
        return True

    def build_all(self, roots):
        """Build one merged catalogue while retaining one cache per root."""
        cancel = self._begin_build()
        if cancel is None:
            return False
        self.ready = False
        with self._analysis_lock:
            self._analysis.suspend_background()
        threading.Thread(
            target=self._build_all_thread, args=(tuple(roots), cancel), daemon=True
        ).start()
        return True

    @property
    def paused(self) -> bool:
        with self._lock:
            return self._paused

    def pause(self) -> bool:
        """Pause new builds and cooperatively cancel the active disk walk."""
        with self._lock:
            changed = not self._paused
            self._paused = True
            self._build_cancel.set()
        self.stop_periodic_flush()
        return changed

    def resume(self) -> bool:
        """Allow builds again; the caller explicitly starts the replacement scan."""
        with self._lock:
            changed = self._paused
            self._paused = False
        return changed

    def _begin_build(self) -> threading.Event | None:
        with self._build_event_gate:
            with self._lock:
                if self._paused:
                    return None
                self._build_cancel.set()
                self._build_cancel = threading.Event()
                token = self._build_cancel
            # A new build starts from the current filesystem state.  Pending
            # callbacks from a superseded build are therefore discarded and
            # only events that happen from this point forward are buffered.
            self._build_event_active = True
            self._build_event_token = token
            self._build_event_queue = []
            self._build_event_overflow = False
            return token

    def defer_live_event_until_build_complete(self, callback) -> bool:
        """Buffer one WATCH mutation while the current rebuild is active.

        Returns True when the caller must stop processing the event now.  The
        callbacks are replayed in arrival order after the scanner atomically
        publishes its replacement catalogue.  The queue is deliberately
        bounded; overflow triggers a second reconciliation build instead of
        silently losing filesystem changes.
        """
        if getattr(self._build_event_replay, "active", False):
            return False
        with self._build_event_gate:
            if not self._build_event_active:
                return False
            if len(self._build_event_queue) < self._build_event_limit:
                self._build_event_queue.append(callback)
            else:
                self._build_event_overflow = True
            return True

    def _finish_live_event_transition(self, token: threading.Event, *, rebuild_args=None) -> None:
        """Replay buffered WATCH events without a gap after a successful build.

        New watcher callbacks block on ``_build_event_gate`` while the queued
        callbacks are replayed, so an event cannot overtake an older buffered
        mutation.  If the bounded queue overflowed we immediately start one
        fresh reconciliation build from disk after releasing the gate.
        """
        overflow = False
        with self._build_event_gate:
            if token is not self._build_event_token:
                return
            callbacks = list(self._build_event_queue)
            overflow = bool(self._build_event_overflow)
            self._build_event_queue = []
            self._build_event_overflow = False
            self._build_event_replay.active = True
            try:
                for callback in callbacks:
                    try:
                        callback()
                    except Exception as exc:
                        state._emit(
                            f"WATCH  buffered event replay failed: {type(exc).__name__}",
                            "warning",
                        )
            finally:
                self._build_event_replay.active = False
                self._build_event_active = False
                self._build_event_token = None

        if overflow and rebuild_args is not None:
            state._emit(
                "WATCH  rebuild event buffer overflow - scheduling reconciliation scan",
                "warning",
            )
            kind, value = rebuild_args
            if kind == "all":
                self.build_all(value)
            else:
                root, root_slot = value
                self.build(root, root_slot)

    def search(self, query: str, limit=50, offset=0, file_type="all", access_filter=None) -> dict:
        """Find matching files by name, optionally filtered to a specific media category."""
        q = query.strip().lower()
        if not q and (not file_type or file_type.lower() == "all"):
            return {"items": [], "total": 0, "offset": offset, "has_more": False}
        filter_type = file_type.lower() if file_type else "all"
        with self._lock:
            if filter_type == "all":
                matched = [
                    self._entries[i]
                    for i, name in enumerate(self._names_lc)
                    if q in name
                ]
            else:
                matched = [
                    self._entries[i]
                    for i, name in enumerate(self._names_lc)
                    if (not q or q in name)
                    and self._get_file_category(self._entries[i]["name"]) == filter_type
                ]
            matched = [
                {
                    key: value for key, value in entry.items()
                    if key not in ("waveform", "integrated_lufs", "analysis_error",
                                   "analysis_error_message",
                                   "cue_out_seconds", "suggested_crossfade_seconds",
                                   "duration_seconds", "analysis_version")
                }
                for entry in matched
            ]
            if access_filter is not None:
                matched = [entry for entry in matched if access_filter(entry)]
        total = len(matched)
        return {
            "items":    matched[offset:offset+limit],
            "total":    total,
            "offset":   offset,
            "has_more": (offset + limit) < total,
        }

    def snapshot_entries(self) -> list[dict]:
        """Return lightweight copies for derived views without rescanning disk."""
        allowed = ("name", "path", "root_slot", "is_dir", "size", "modified", "bpm")
        with self._lock:
            return [
                {key: entry.get(key) for key in allowed if key in entry}
                for entry in self._entries
            ]

    def add_file(self, path: Path, root: Path, root_slot: str = PRIMARY_ROOT_SLOT):
        """Add or update a single file entry in the in-memory index."""
        try:
            relative = "/" + path.relative_to(root).as_posix()
        except ValueError:
            return
        if (not path.is_file() or path.name.startswith(".") or
                is_inside_hidden_folder(path, root) or is_config_hidden(root_slot, relative)):
            return
        try:
            stat  = path.stat()
            rel   = str(path.relative_to(root)).replace("\\", "/")
            entry = {
                "name":     path.name,
                "path":     f"/{rel}",
                "root_slot": root_slot,
                "is_dir":   False,
                "size":     stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            }
            lc = path.name.lower()
            with self._lock:
                for i, e in enumerate(self._entries):
                    if e.get("root_slot", PRIMARY_ROOT_SLOT) == root_slot and e["path"] == entry["path"]:
                        self._entries[i]  = entry
                        self._names_lc[i] = lc
                        self._dirty = True
                        self._submit_analysis(entry["path"], path)
                        return
                self._entries.append(entry)
                self._names_lc.append(lc)
                self.total  += 1
                self._dirty  = True
            self._submit_analysis(entry["path"], path)
        except (PermissionError, OSError):
            pass

    def remove_file(self, rel_path: str, root_slot: str = PRIMARY_ROOT_SLOT):
        """Remove a file entry from the index when it has been deleted."""
        with self._lock:
            for i, e in enumerate(self._entries):
                if e.get("root_slot", PRIMARY_ROOT_SLOT) == root_slot and e["path"] == rel_path:
                    self._entries.pop(i)
                    self._names_lc.pop(i)
                    self.total  -= 1
                    self._dirty  = True
                    return

    def remove_tree(self, rel_dir: str, root_slot: str = PRIMARY_ROOT_SLOT):
        """Remove every indexed file below a directory that became hidden."""
        prefix = "/" + str(rel_dir or "").strip("/\\")
        prefix = prefix.rstrip("/") + "/"
        with self._lock:
            kept = [
                (entry, name)
                for entry, name in zip(self._entries, self._names_lc)
                if not (
                    entry.get("root_slot", PRIMARY_ROOT_SLOT) == root_slot
                    and entry["path"].startswith(prefix)
                )
            ]
            if len(kept) == len(self._entries):
                return
            self._entries = [entry for entry, _ in kept]
            self._names_lc = [name for _, name in kept]
            self.total = len(self._entries)
            self._dirty = True

    def invalidate_cache(self, root):
        try:
            self._cache_path(root).unlink(missing_ok=True)
        except Exception:
            pass

    def flush_if_dirty(self, root, root_slot: str = PRIMARY_ROOT_SLOT):
        if self._dirty and self.ready:
            self._save_cache(root, root_slot)
            self._dirty = False

    def flush_all_if_dirty(self, roots):
        if self._dirty and self.ready:
            for shared_root in roots:
                self._save_cache(shared_root.path, shared_root.slot)
            self._dirty = False

    def clear(self):
        self.stop_periodic_flush()
        with self._lock:
            self._entries  = []
            self._names_lc = []
            self.total     = 0
            self.ready     = False
            self._dirty    = False

    def get_analysis(self, rel_path: str, root_slot: str = PRIMARY_ROOT_SLOT) -> dict | None:
        """Return enriched media fields for one indexed file."""
        with self._lock:
            for entry in self._entries:
                if entry.get("root_slot", PRIMARY_ROOT_SLOT) == root_slot and entry["path"] == rel_path:
                    fields = {
                        key: entry.get(key)
                        for key in ("analysis_version", "integrated_lufs", "loudness_gain", "waveform", "bpm",
                                    "duration_seconds", "cue_out_seconds",
                                    "suggested_crossfade_seconds", "analysis_error",
                                    "analysis_error_message")
                        if key in entry
                    }
                    return fields or None
        return None

    def loudness_gain(self, rel_path: str, root_slot: str = PRIMARY_ROOT_SLOT) -> float | None:
        analysis = self.get_analysis(rel_path, root_slot)
        return analysis.get("loudness_gain") if analysis else None

    def bpm(self, rel_path: str, root_slot: str = PRIMARY_ROOT_SLOT) -> float | None:
        analysis = self.get_analysis(rel_path, root_slot)
        return analysis.get("bpm") if analysis else None

    def schedule_analysis(self, rel_path: str, absolute_path: Path) -> bool:
        # Interactive requests must jump ahead of the background migration.
        return self._submit_analysis(rel_path, absolute_path, priority=True)

    def rescan_media(self, root: Path):
        """Forget enriched fields and progressively requeue all indexed audio."""
        with self._lock:
            for entry in self._entries:
                for key in ("analysis_version", "integrated_lufs", "loudness_gain", "waveform", "bpm",
                            "duration_seconds", "cue_out_seconds",
                            "suggested_crossfade_seconds", "analysis_error",
                            "analysis_error_message"):
                    entry.pop(key, None)
            self._dirty = True
        self._schedule_existing_audio(Path(root))

    def _store_analysis(self, rel_path: str, result: dict):
        with self._lock:
            for entry in self._entries:
                if entry["path"] == rel_path:
                    entry.update(result)
                    self._dirty = True
                    break

    def _schedule_existing_audio(self, root: Path):
        """Low-priority migration: queue legacy audio after the base index is ready."""
        with self._lock:
            candidates = [
                e["path"] for e in self._entries
                if e.get("analysis_version") != ANALYSIS_VERSION
                and is_audio(Path(e["name"]))
            ]
        for rel_path in candidates:
            if not self._submit_analysis(rel_path, root / rel_path.lstrip("/")):
                state._emit("ANALYSIS  queue full - background item deferred", "dim")
                break

    def start_periodic_flush(self, root, interval: int = 300):
        self.stop_periodic_flush()
        self._flush_stop.clear()

        def _loop():
            while not self._flush_stop.wait(timeout=interval):
                if self._dirty and self.ready:
                    self._save_cache(root)
                    self._dirty = False

        t = threading.Thread(target=_loop, daemon=True, name="index-flush")
        t.start()
        self._flush_thread = t

    def start_periodic_flush_all(self, roots, interval: int = 300):
        roots = tuple(roots)
        self.stop_periodic_flush()
        self._flush_stop.clear()

        def _loop():
            while not self._flush_stop.wait(timeout=interval):
                self.flush_all_if_dirty(roots)

        self._flush_thread = threading.Thread(
            target=_loop, daemon=True, name="index-flush",
        )
        self._flush_thread.start()

    def stop_periodic_flush(self):
        self._flush_stop.set()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=2)
        self._flush_thread = None

    # Internal build pipeline

    def _build_thread(self, root: Path, root_slot: str, cancel: threading.Event):
        completed = False
        try:
            if cancel.is_set():
                return
            if self._try_load_cache(root, root_slot):
                if not self._apply_offline_diff(root, root_slot, cancel):
                    return
                self._save_cache(root, root_slot)
                self._schedule_existing_audio(root)
                completed = not cancel.is_set()
                return
            if not self._scan(root, root_slot, cancel):
                return
            self._save_cache(root, root_slot)
            self._schedule_existing_audio(root)
            completed = not cancel.is_set()
        finally:
            self._finish_live_event_transition(
                cancel,
                rebuild_args=("one", (root, root_slot)) if completed else None,
            )
            self._finish_build_resource_transition()

    def _build_all_thread(self, roots, cancel: threading.Event):
        completed = False
        try:
            merged = []
            for shared_root in roots:
                if cancel.is_set():
                    return
                if self._try_load_cache(shared_root.path, shared_root.slot):
                    if not self._apply_offline_diff(shared_root.path, shared_root.slot, cancel):
                        return
                else:
                    if not self._scan(shared_root.path, shared_root.slot, cancel):
                        return
                with self._lock:
                    current = list(self._entries)
                self._save_cache(shared_root.path, shared_root.slot)
                self._schedule_existing_audio(shared_root.path)
                merged.extend(current)
                self.ready = False
            if cancel.is_set():
                return
            with self._lock:
                self._entries = merged
                self._names_lc = [entry["name"].lower() for entry in merged]
                self.total = len(merged)
                self.ready = True
            completed = True
        finally:
            self._finish_live_event_transition(
                cancel,
                rebuild_args=("all", tuple(roots)) if completed else None,
            )
            self._finish_build_resource_transition()

    def _try_load_cache(self, root: Path, root_slot: str = PRIMARY_ROOT_SLOT) -> bool:
        cache_file = self._cache_path(root)
        if not cache_file.exists():
            return False
        try:
            t0 = _time.monotonic()
            state._emit("INDEX  loading cache...", "dim")
            compressed = read_bytes(cache_file, purpose=f"file-index:{root_slot}")
            data = json.loads(gzip.decompress(compressed).decode("utf-8"))
            if data.get("root") != str(root):
                state._emit("INDEX  cache mismatch - full scan needed", "dim")
                return False
            entries  = data["entries"]
            for entry in entries:
                entry["root_slot"] = root_slot
            names_lc = [e["name"].lower() for e in entries]
            with self._lock:
                self._entries  = entries
                self._names_lc = names_lc
                self._built_at = data.get("built_at", 0.0)
                self.total     = len(entries)
                self.ready     = True
            state._emit(
                f"INDEX  cache loaded - {self.total:,} files  [{_time.monotonic()-t0:.1f}s]",
                "dim",
            )
            return True
        except Exception as e:
            state._emit(f"INDEX  cache load failed ({e}) - full scan", "dim")
            return False

    def _apply_offline_diff(
        self, root: Path, root_slot: str, cancel: threading.Event,
    ) -> bool:
        state._emit("INDEX  checking for offline changes...", "dim")
        t0 = _time.monotonic()
        with self._lock:
            cache_map = {
                e["path"]: e["modified"]
                for e in self._entries
                if e.get("root_slot", PRIMARY_ROOT_SLOT) == root_slot
            }
        added = updated = 0
        on_disk = set()
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                if cancel.is_set():
                    return False
                base = Path(dirpath)
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".") and not is_hidden_folder(base / d)
                ]
                for fname in filenames:
                    if fname.startswith("."):
                        continue
                    fpath = base / fname
                    try:
                        stat      = fpath.stat()
                        rel       = "/" + str(fpath.relative_to(root)).replace("\\", "/")
                        rel       = rel.encode("utf-8", errors="replace").decode("utf-8")
                        mtime_str = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                        on_disk.add(rel)
                        if rel not in cache_map:
                            fc    = fname.encode("utf-8", errors="replace").decode("utf-8")
                            entry = {
                                "name": fc, "path": rel, "is_dir": False,
                                "root_slot": root_slot,
                                "size": stat.st_size, "modified": mtime_str,
                            }
                            with self._lock:
                                self._entries.append(entry)
                                self._names_lc.append(fc.lower())
                                self.total += 1
                            added += 1
                        elif cache_map[rel] != mtime_str:
                            fc    = fname.encode("utf-8", errors="replace").decode("utf-8")
                            entry = {
                                "name": fc, "path": rel, "is_dir": False,
                                "root_slot": root_slot,
                                "size": stat.st_size, "modified": mtime_str,
                            }
                            with self._lock:
                                for i, e in enumerate(self._entries):
                                    if e.get("root_slot", PRIMARY_ROOT_SLOT) == root_slot and e["path"] == rel:
                                        self._entries[i]  = entry
                                        self._names_lc[i] = fc.lower()
                                        break
                            updated += 1
                    except (PermissionError, OSError):
                        pass
        except Exception as e:
            state._emit(f"INDEX  diff walk error: {e}", "error")

        removed_paths = set(cache_map.keys()) - on_disk
        for rel in removed_paths:
            self.remove_file(rel, root_slot)
        removed = len(removed_paths)
        elapsed = _time.monotonic() - t0

        if added or updated or removed:
            state._emit(
                f"INDEX  diff done  +{added}  ~{updated}  -{removed}  [{elapsed:.1f}s]", "ok"
            )
        else:
            state._emit(f"INDEX  diff done  no changes  [{elapsed:.1f}s]", "dim")
        state._emit(f"INDEX  ready - {self.total:,} files", "ok")
        return True

    def _save_cache(self, root, root_slot: str = PRIMARY_ROOT_SLOT):
        cache_file = self._cache_path(root)
        try:
            state._emit("INDEX  saving cache...", "dim")
            with self._lock:
                entries = [
                    dict(entry)
                    for entry in self._entries
                    if entry.get("root_slot", PRIMARY_ROOT_SLOT) == root_slot
                ]
            payload = json.dumps(
                {"schema": 2, "root": str(root), "built_at": _time.time(), "entries": entries},
                ensure_ascii=True,
            ).encode("utf-8")
            compressed = gzip.compress(payload, compresslevel=1)
            write_bytes(cache_file, compressed, purpose=f"file-index:{root_slot}")
            size_mb = cache_file.stat().st_size / 1_048_576
            state._emit(f"INDEX  cache saved  ({size_mb:.1f} MB)", "dim")
        except Exception as e:
            state._emit(f"INDEX  cache save failed: {e}", "error")

    def _scan(
        self, root: Path, root_slot: str, cancel: threading.Event,
    ) -> bool:
        state._emit("INDEX  scanning... (first run - will be cached)", "dim")
        entries = []; names_lc = []; count = 0

        def paths():
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                if cancel.is_set():
                    return
                base = Path(dirpath)
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".") and not is_hidden_folder(base / d)
                ]
                for filename in filenames:
                    if not filename.startswith("."):
                        yield base / filename

        def inspect(fpath: Path):
            try:
                stat = fpath.stat()
                rel = str(fpath.relative_to(root)).replace("\\", "/")
                filename = fpath.name.encode("utf-8", errors="replace").decode("utf-8")
                rel = rel.encode("utf-8", errors="replace").decode("utf-8")
                return {
                    "name": filename, "path": f"/{rel}", "is_dir": False,
                    "root_slot": root_slot,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                }
            except (PermissionError, OSError):
                return None

        budget = self._current_worker_budget()
        try:
            with ThreadPoolExecutor(max_workers=budget.index_workers, thread_name_prefix="index") as executor:
                for entry in executor.map(inspect, paths()):
                    if cancel.is_set():
                        return False
                    if entry is not None:
                        entries.append(entry)
                        names_lc.append(entry["name"].lower())
                        count += 1
                        if count % 50_000 == 0:
                            state._emit(f"INDEX  {count:,} files...", "dim")
        except Exception as e:
            state._emit(f"INDEX  scan error: {e}", "error")
        if cancel.is_set():
            return False
        with self._lock:
            self._entries  = entries
            self._names_lc = names_lc
            self.total     = count
            self.ready     = True
        state._emit(f"INDEX  ready - {count:,} files", "ok")
        return True

    # File-type classifier

    @classmethod
    def _get_file_category(cls, filename: str) -> str:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        for category, exts in cls._TYPE_EXTENSIONS.items():
            if ext in exts:
                return category
        return "other"


# Module-level singleton

_file_index = FileIndex()


# Directory watcher

class _IndexEventHandler(_WatchdogBase):
    def __init__(
        self, root: Path, root_slot: str = PRIMARY_ROOT_SLOT, dispatcher=None,
    ):
        if HAS_WATCHDOG:
            super().__init__()
        self._root = root
        self._root_slot = root_slot
        self._dispatcher = dispatcher
        self._dispatch_local = threading.local()

    def _defer(self, event_type: str, event) -> bool:
        if self._dispatcher is None or getattr(self._dispatch_local, "active", False):
            return False
        src_path = getattr(event, "src_path", None)
        dest_path = getattr(event, "dest_path", None)
        if event_type == "moved":
            # Ignore a move only when both ends are internal/hidden.  A visible
            # -> hidden or hidden -> visible rename must still update the index.
            if (
                _watch_path_is_internal_or_hidden(self._root, src_path)
                and _watch_path_is_internal_or_hidden(self._root, dest_path)
            ):
                return True
        elif _watch_path_is_internal_or_hidden(self._root, src_path):
            return True
        path = dest_path or src_path
        key = (self._root_slot, str(path), event_type)

        def callback():
            self._dispatch_local.active = True
            try:
                getattr(self, f"on_{event_type}")(event)
            finally:
                self._dispatch_local.active = False

        self._dispatcher.submit(key, callback)
        return True

    def _defer_for_rebuild(self, event_type: str, event) -> bool:
        if getattr(self._dispatch_local, "build_replay", False):
            return False
        from types import SimpleNamespace
        frozen_event = SimpleNamespace(
            is_directory=bool(getattr(event, "is_directory", False)),
            src_path=str(getattr(event, "src_path", "") or ""),
            dest_path=str(getattr(event, "dest_path", "") or ""),
        )

        def callback():
            self._dispatch_local.build_replay = True
            try:
                getattr(self, f"on_{event_type}")(frozen_event)
            finally:
                self._dispatch_local.build_replay = False

        return _file_index.defer_live_event_until_build_complete(callback)

    def _rel(self, abs_path: str) -> str:
        try:
            return "/" + str(Path(abs_path).relative_to(self._root)).replace("\\", "/")
        except ValueError:
            return abs_path

    def _broadcast(self, payload: dict):
        if state._ws_manager:
            import json as _json
            state._ws_manager.broadcast_threadsafe(_json.dumps(payload))

    def _public_rel(self, rel: str) -> str:
        return public_shared_path(self._root_slot, rel)

    def on_created(self, event):
        if self._defer("created", event):
            return
        if self._defer_for_rebuild("created", event):
            return
        if _watch_path_is_internal_or_hidden(self._root, event.src_path):
            return
        path = Path(event.src_path)
        rel  = self._rel(event.src_path)
        if event.is_directory:
            state._emit(f"WATCH  dir  added   {rel}", "dim")
            self._broadcast({
                "type": "dir_added",
                "path": self._public_rel(rel),
                "folder_name": path.name,
            })
        else:
            if path.name.startswith("."):
                return
            _file_index.add_file(path, self._root, self._root_slot)
            state._emit(f"WATCH  file added   {rel}", "dim")
            self._broadcast({
                "type": "file_added",
                "path": self._public_rel(rel),
                "file_name": path.name,
            })

    def on_deleted(self, event):
        if self._defer("deleted", event):
            return
        if self._defer_for_rebuild("deleted", event):
            return
        if _watch_path_is_internal_or_hidden(self._root, event.src_path):
            return
        rel = self._rel(event.src_path)
        if event.is_directory:
            prefix    = rel.rstrip("/") + "/"
            with _file_index._lock:
                to_remove = [
                    e["path"] for e in _file_index._entries
                    if e["path"].startswith(prefix)
                ]
            for p in to_remove:
                _file_index.remove_file(p, self._root_slot)
            state._emit(
                f"WATCH  dir  removed {rel}  ({len(to_remove)} files)", "dim"
            )
            self._broadcast({
                "type": "dir_removed", "path": self._public_rel(rel),
                "files_removed": len(to_remove),
            })
        else:
            _file_index.remove_file(rel, self._root_slot)
            state._emit(f"WATCH  file removed {rel}", "dim")
            self._broadcast({"type": "file_removed", "path": self._public_rel(rel)})

    def on_moved(self, event):
        if self._defer("moved", event):
            return
        if self._defer_for_rebuild("moved", event):
            return
        src_hidden = _watch_path_is_internal_or_hidden(self._root, event.src_path)
        dest_hidden = _watch_path_is_internal_or_hidden(self._root, event.dest_path)
        if src_hidden and dest_hidden:
            return
        src_rel  = self._rel(event.src_path)
        dest_rel = self._rel(event.dest_path)
        dest_path = Path(event.dest_path)
        if event.is_directory:
            # Dot/hidden directory transitions are intentionally absent from the
            # catalogue.  Avoid publishing internal metadata moves.
            if src_hidden or dest_hidden:
                return
            src_p  = src_rel.rstrip("/")  + "/"
            dest_p = dest_rel.rstrip("/") + "/"
            with _file_index._lock:
                for entry in _file_index._entries:
                    if entry["path"].startswith(src_p):
                        entry["path"] = dest_p + entry["path"][len(src_p):]
            state._emit(f"WATCH  dir  moved   {src_rel} -> {dest_rel}", "dim")
            self._broadcast({
                "type": "dir_moved",
                "src": self._public_rel(src_rel),
                "dest": self._public_rel(dest_rel),
            })
        else:
            if not src_hidden:
                _file_index.remove_file(src_rel, self._root_slot)
            if not dest_hidden:
                _file_index.add_file(dest_path, self._root, self._root_slot)
            if src_hidden:
                state._emit(f"WATCH  file added   {dest_rel}", "dim")
                self._broadcast({
                    "type": "file_added",
                    "path": self._public_rel(dest_rel),
                    "file_name": dest_path.name,
                })
            elif dest_hidden:
                state._emit(f"WATCH  file removed {src_rel}", "dim")
                self._broadcast({"type": "file_removed", "path": self._public_rel(src_rel)})
            else:
                state._emit(f"WATCH  file moved   {src_rel} -> {dest_rel}", "dim")
                self._broadcast({
                    "type": "file_moved",
                    "src": self._public_rel(src_rel),
                    "dest": self._public_rel(dest_rel),
                })

    def on_modified(self, event):
        if self._defer("modified", event):
            return
        if self._defer_for_rebuild("modified", event):
            return
        if event.is_directory or _watch_path_is_internal_or_hidden(self._root, event.src_path):
            return
        path = Path(event.src_path)
        if path.name.startswith("."):
            return
        _file_index.add_file(path, self._root, self._root_slot)
        self._broadcast({
            "type": "file_modified",
            "path": self._public_rel(self._rel(event.src_path)),
        })


def _start_watcher(root: Path):
    global _dir_observer, _watch_event_coalescer
    if not HAS_WATCHDOG:
        state._emit("WATCH  watchdog not installed - live updates disabled", "dim")
        state._emit("->  pip install watchdog", "dim")
        return
    _stop_watcher()
    _watch_event_coalescer = _new_watch_event_coalescer()
    _watch_event_coalescer.start()
    handler  = _IndexEventHandler(root, dispatcher=_watch_event_coalescer)
    observer = Observer()
    observer.schedule(handler, str(root), recursive=True)
    observer.daemon = True
    observer.start()
    _dir_observer = observer
    state._emit(f"WATCH  watching {root}", "ok")


def _start_watchers(roots):
    """Replace the active observer with schedules for every configured root."""
    global _dir_observer, _watch_event_coalescer
    if not HAS_WATCHDOG:
        state._emit("WATCH  watchdog not installed - live updates disabled", "dim")
        return
    roots = tuple(roots)
    _stop_watcher()
    _watch_event_coalescer = _new_watch_event_coalescer()
    _watch_event_coalescer.start()
    observer = Observer()
    for shared_root in roots:
        observer.schedule(
            _IndexEventHandler(
                shared_root.path, shared_root.slot,
                dispatcher=_watch_event_coalescer,
            ),
            str(shared_root.path),
            recursive=True,
        )
    observer.daemon = True
    observer.start()
    _dir_observer = observer
    state._emit(f"WATCH  watching {len(roots)} shared root(s)", "ok")


def _stop_watcher():
    global _dir_observer, _watch_event_coalescer
    if _dir_observer is not None:
        try:
            _dir_observer.stop()
            _dir_observer.join(timeout=2)
        except Exception:
            pass
        _dir_observer = None
    if _watch_event_coalescer is not None:
        _watch_event_coalescer.stop()
        _watch_event_coalescer = None
