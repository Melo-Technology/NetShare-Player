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
from datetime import datetime
from pathlib import Path

import src.state as state
from src.deps import HAS_WATCHDOG

if HAS_WATCHDOG:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler as _WatchdogBase
else:
    _WatchdogBase = object   # dummy base so the class still parses

_dir_observer = None


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

    # Cache paths

    @staticmethod
    def _cache_path(root) -> Path:
        return Path(root) / FileIndex.CACHE_FILENAME

    # Public API

    def build(self, root):
        """Start rebuilding the index from the filesystem in the background."""
        self.ready = False
        threading.Thread(
            target=self._build_thread, args=(Path(root),), daemon=True
        ).start()

    def search(self, query: str, limit=50, offset=0, file_type="all") -> dict:
        """Find matching files by name, optionally filtered to a specific media category."""
        q = query.strip().lower()
        if not q:
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
                    if q in name
                    and self._get_file_category(self._entries[i]["name"]) == filter_type
                ]
        total = len(matched)
        return {
            "items":    matched[offset:offset+limit],
            "total":    total,
            "offset":   offset,
            "has_more": (offset + limit) < total,
        }

    def add_file(self, path: Path, root: Path):
        """Add or update a single file entry in the in-memory index."""
        if not path.is_file() or path.name.startswith("."):
            return
        try:
            stat  = path.stat()
            rel   = str(path.relative_to(root)).replace("\\", "/")
            entry = {
                "name":     path.name,
                "path":     f"/{rel}",
                "is_dir":   False,
                "size":     stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            }
            lc = path.name.lower()
            with self._lock:
                for i, e in enumerate(self._entries):
                    if e["path"] == entry["path"]:
                        self._entries[i]  = entry
                        self._names_lc[i] = lc
                        return
                self._entries.append(entry)
                self._names_lc.append(lc)
                self.total  += 1
                self._dirty  = True
        except (PermissionError, OSError):
            pass

    def remove_file(self, rel_path: str):
        """Remove a file entry from the index when it has been deleted."""
        with self._lock:
            for i, e in enumerate(self._entries):
                if e["path"] == rel_path:
                    self._entries.pop(i)
                    self._names_lc.pop(i)
                    self.total  -= 1
                    self._dirty  = True
                    return

    def invalidate_cache(self, root):
        try:
            self._cache_path(root).unlink(missing_ok=True)
        except Exception:
            pass

    def flush_if_dirty(self, root):
        if self._dirty and self.ready:
            self._save_cache(root)
            self._dirty = False

    def clear(self):
        self.stop_periodic_flush()
        with self._lock:
            self._entries  = []
            self._names_lc = []
            self.total     = 0
            self.ready     = False
            self._dirty    = False

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

    def stop_periodic_flush(self):
        self._flush_stop.set()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=2)
        self._flush_thread = None

    # Internal build pipeline

    def _build_thread(self, root: Path):
        if self._try_load_cache(root):
            self._apply_offline_diff(root)
            self._save_cache(root)
            return
        self._scan(root)
        self._save_cache(root)

    def _try_load_cache(self, root: Path) -> bool:
        cache_file = self._cache_path(root)
        if not cache_file.exists():
            return False
        try:
            t0 = _time.monotonic()
            state._emit("INDEX  loading cache...", "dim")
            with gzip.open(cache_file, "rb") as f:
                data = json.loads(f.read().decode("utf-8"))
            if data.get("root") != str(root):
                state._emit("INDEX  cache mismatch - full scan needed", "dim")
                return False
            entries  = data["entries"]
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

    def _apply_offline_diff(self, root: Path):
        state._emit("INDEX  checking for offline changes...", "dim")
        t0 = _time.monotonic()
        with self._lock:
            cache_map = {e["path"]: e["modified"] for e in self._entries}
        added = updated = 0
        on_disk = set()
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                base = Path(dirpath)
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
                                "size": stat.st_size, "modified": mtime_str,
                            }
                            with self._lock:
                                for i, e in enumerate(self._entries):
                                    if e["path"] == rel:
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
            self.remove_file(rel)
        removed = len(removed_paths)
        elapsed = _time.monotonic() - t0

        if added or updated or removed:
            state._emit(
                f"INDEX  diff done  +{added}  ~{updated}  -{removed}  [{elapsed:.1f}s]", "ok"
            )
        else:
            state._emit(f"INDEX  diff done  no changes  [{elapsed:.1f}s]", "dim")
        state._emit(f"INDEX  ready - {self.total:,} files", "ok")

    def _save_cache(self, root):
        cache_file = self._cache_path(root)
        try:
            state._emit("INDEX  saving cache...", "dim")
            with self._lock:
                entries = list(self._entries)
            payload = json.dumps(
                {"root": str(root), "built_at": _time.time(), "entries": entries},
                ensure_ascii=True,
            ).encode("utf-8")
            tmp = cache_file.with_suffix(".tmp")
            with gzip.open(tmp, "wb", compresslevel=1) as f:
                f.write(payload)
            tmp.replace(cache_file)
            size_mb = cache_file.stat().st_size / 1_048_576
            state._emit(f"INDEX  cache saved  ({size_mb:.1f} MB)", "dim")
        except Exception as e:
            state._emit(f"INDEX  cache save failed: {e}", "error")

    def _scan(self, root: Path):
        state._emit("INDEX  scanning... (first run - will be cached)", "dim")
        entries = []; names_lc = []; count = 0
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                base = Path(dirpath)
                for fname in filenames:
                    if fname.startswith("."):
                        continue
                    fpath = base / fname
                    try:
                        stat  = fpath.stat()
                        rel   = str(fpath.relative_to(root)).replace("\\", "/")
                        fname = fname.encode("utf-8", errors="replace").decode("utf-8")
                        rel   = rel.encode("utf-8", errors="replace").decode("utf-8")
                        entry = {
                            "name":     fname,
                            "path":     f"/{rel}",
                            "is_dir":   False,
                            "size":     stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        }
                        entries.append(entry)
                        names_lc.append(fname.lower())
                        count += 1
                        if count % 50_000 == 0:
                            state._emit(f"INDEX  {count:,} files...", "dim")
                    except (PermissionError, OSError):
                        pass
        except Exception as e:
            state._emit(f"INDEX  scan error: {e}", "error")
        with self._lock:
            self._entries  = entries
            self._names_lc = names_lc
            self.total     = count
            self.ready     = True
        state._emit(f"INDEX  ready - {count:,} files", "ok")

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
    def __init__(self, root: Path):
        if HAS_WATCHDOG:
            super().__init__()
        self._root = root

    def _rel(self, abs_path: str) -> str:
        try:
            return "/" + str(Path(abs_path).relative_to(self._root)).replace("\\", "/")
        except ValueError:
            return abs_path

    def _broadcast(self, payload: dict):
        if state._ws_manager:
            import json as _json
            state._ws_manager.broadcast_threadsafe(_json.dumps(payload))

    def on_created(self, event):
        path = Path(event.src_path)
        rel  = self._rel(event.src_path)
        if event.is_directory:
            state._emit(f"WATCH  dir  added   {rel}", "dim")
            self._broadcast({"type": "dir_added", "path": rel})
        else:
            if path.name.startswith("."):
                return
            _file_index.add_file(path, self._root)
            state._emit(f"WATCH  file added   {rel}", "dim")
            self._broadcast({"type": "file_added", "path": rel})

    def on_deleted(self, event):
        rel = self._rel(event.src_path)
        if event.is_directory:
            prefix    = rel.rstrip("/") + "/"
            with _file_index._lock:
                to_remove = [
                    e["path"] for e in _file_index._entries
                    if e["path"].startswith(prefix)
                ]
            for p in to_remove:
                _file_index.remove_file(p)
            state._emit(
                f"WATCH  dir  removed {rel}  ({len(to_remove)} files)", "dim"
            )
            self._broadcast({
                "type": "dir_removed", "path": rel,
                "files_removed": len(to_remove),
            })
        else:
            _file_index.remove_file(rel)
            state._emit(f"WATCH  file removed {rel}", "dim")
            self._broadcast({"type": "file_removed", "path": rel})

    def on_moved(self, event):
        src_rel  = self._rel(event.src_path)
        dest_rel = self._rel(event.dest_path)
        dest_path = Path(event.dest_path)
        if event.is_directory:
            src_p  = src_rel.rstrip("/")  + "/"
            dest_p = dest_rel.rstrip("/") + "/"
            with _file_index._lock:
                for entry in _file_index._entries:
                    if entry["path"].startswith(src_p):
                        entry["path"] = dest_p + entry["path"][len(src_p):]
            state._emit(f"WATCH  dir  moved   {src_rel} -> {dest_rel}", "dim")
            self._broadcast({"type": "dir_moved", "src": src_rel, "dest": dest_rel})
        else:
            _file_index.remove_file(src_rel)
            if not dest_path.name.startswith("."):
                _file_index.add_file(dest_path, self._root)
            state._emit(f"WATCH  file moved   {src_rel} -> {dest_rel}", "dim")
            self._broadcast({"type": "file_moved", "src": src_rel, "dest": dest_rel})

    def on_modified(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.name.startswith("."):
            return
        _file_index.add_file(path, self._root)
        self._broadcast({"type": "file_modified", "path": self._rel(event.src_path)})


def _start_watcher(root: Path):
    global _dir_observer
    if not HAS_WATCHDOG:
        state._emit("WATCH  watchdog not installed - live updates disabled", "dim")
        state._emit("->  pip install watchdog", "dim")
        return
    _stop_watcher()
    handler  = _IndexEventHandler(root)
    observer = Observer()
    observer.schedule(handler, str(root), recursive=True)
    observer.daemon = True
    observer.start()
    _dir_observer = observer
    state._emit(f"WATCH  watching {root}", "ok")


def _stop_watcher():
    global _dir_observer
    if _dir_observer is not None:
        try:
            _dir_observer.stop()
            _dir_observer.join(timeout=2)
        except Exception:
            pass
        _dir_observer = None
