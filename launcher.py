#!/usr/bin/env python3
"""
NetShare Player — GUI Launcher
===============================
Visual launcher for the NetShare HTTP + WebSocket server.
Design: monochrome, geometric, Share Tech Mono aesthetic.
Author: Daniel Joy

Usage:
    python launcher.py
    Use Ngrok to expose your files to the internet.

Requires:
    pip install websockets
    pip install qrcode
    pip install pillow
    pip install watchdog
"""

import asyncio
import json
import mimetypes
import os
import queue
import socket
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from tkinter import filedialog, messagebox, PhotoImage
from urllib.parse import parse_qs, unquote, urlparse

import tkinter as tk
import tkinter.font as tkfont

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    import websockets
    import websockets.server
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    from PIL import Image as PilImage
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ── Theme system ───────────────────────────────────────────────────────────────

_DARK = {
    "BG":        "#000000",
    "SURFACE":   "#0f0f0f",
    "SURFACE2":  "#1a1a1a",
    "BORDER":    "#2a2a2a",
    "BORDER2":   "#3a3a3a",
    "FG":        "#ffffff",
    "FG2":       "#737373",
    "FG3":       "#404040",
    "DANGER":    "#cc0000",
    "TOGGLE_BG": "#1a1a1a",
    "TOGGLE_FG": "#737373",
}

_LIGHT = {
    "BG":        "#f5f5f5",
    "SURFACE":   "#ffffff",
    "SURFACE2":  "#e8e8e8",
    "BORDER":    "#d0d0d0",
    "BORDER2":   "#b0b0b0",
    "FG":        "#0a0a0a",
    "FG2":       "#555555",
    "FG3":       "#aaaaaa",
    "DANGER":    "#cc0000",
    "TOGGLE_BG": "#e8e8e8",
    "TOGGLE_FG": "#555555",
}

_theme: dict = dict(_DARK)

def BG()       : return _theme["BG"]
def SURFACE()  : return _theme["SURFACE"]
def SURFACE2() : return _theme["SURFACE2"]
def BORDER()   : return _theme["BORDER"]
def FG()       : return _theme["FG"]
def FG2()      : return _theme["FG2"]
def FG3()      : return _theme["FG3"]
def DANGER()   : return _theme["DANGER"]

FONT_MONO = "Courier New"


# ── Server constants ───────────────────────────────────────────────────────────

VERSION      = "1.2.0"
DEFAULT_PORT = 8080
MAX_HISTORY  = 6

ROOT_DIR: Path       = Path.cwd()
SERVER_NAME: str     = socket.gethostname()
SERVER_PASSWORD: str = ""
_log_callback        = None
_log_queue: queue.Queue = queue.Queue()


# ── Single-instance lock ───────────────────────────────────────────────────────

def _get_platform():
    """Return a normalized platform identifier: 'mac', 'windows', or 'linux'."""
    p = sys.platform
    if p == "darwin": return "mac"
    elif p.startswith("win"): return "windows"
    else: return "linux"

PLATFORM = _get_platform()

_win_mutex_handle = None


def _ensure_single_instance():
    """
    Prevent multiple instances of the application from running simultaneously.

    Uses a different locking mechanism depending on the platform:
    - Windows: a named Win32 mutex — automatically released by the OS on crash.
    - Linux: an abstract Unix domain socket — disappears when the process dies,
      no file left on disk.
    - macOS / other Unix: a PID lock file in the system temp directory.
    """
    if PLATFORM == "windows":
        _ensure_single_instance_windows()
    elif PLATFORM == "linux":
        _ensure_single_instance_linux()
    else:
        _ensure_single_instance_lockfile()


def _show_already_running():
    """Display a warning dialog informing the user that an instance is already running, then exit."""
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning(
        "NetShare Player",
        "An instance is already running.",
    )
    root.destroy()
    sys.exit(0)


# ── Windows ────────────────────────────────────────────────────────────────────

def _ensure_single_instance_windows():
    """
    Use a named Win32 mutex to enforce single-instance on Windows.

    The mutex handle is kept alive for the entire process lifetime.
    If the mutex already exists, show a warning and exit.
    """
    global _win_mutex_handle
    import ctypes
    ERROR_ALREADY_EXISTS = 183

    handle = ctypes.windll.kernel32.CreateMutexW(
        None, False, "Global\\NetSharePlayer_SingleInstance_v1"
    )
    err = ctypes.windll.kernel32.GetLastError()

    if err == ERROR_ALREADY_EXISTS:
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        _show_already_running()

    _win_mutex_handle = handle


# ── Linux (abstract socket) ────────────────────────────────────────────────────

_linux_lock_sock = None


def _ensure_single_instance_linux():
    """
    Use an abstract Unix domain socket to enforce single-instance on Linux.

    The socket lives in the kernel's abstract namespace and is automatically
    released when the process terminates, even on crash. No file is written
    to disk.
    """
    global _linux_lock_sock
    import socket as _sock

    LOCK_NAME = b"\x00NetSharePlayer_SingleInstance_v1"

    sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    try:
        sock.bind(LOCK_NAME)
    except OSError:
        sock.close()
        _show_already_running()

    _linux_lock_sock = sock


# ── macOS / generic Unix (PID lock file) ──────────────────────────────────────

import tempfile
import atexit

_LOCK_FILE = Path(tempfile.gettempdir()) / "netshare_player_v1.lock"


def _ensure_single_instance_lockfile():
    """
    Enforce single-instance on macOS and other Unix systems using a PID lock file.

    If the lock file exists and the recorded PID is still alive, show a warning
    and exit. If the PID is stale (crashed process) or the file is corrupted,
    overwrite it with the current PID.
    """
    if _LOCK_FILE.exists():
        try:
            pid = int(_LOCK_FILE.read_text().strip())
            os.kill(pid, 0)
            _show_already_running()
        except (ProcessLookupError, PermissionError):
            pass
        except ValueError:
            pass

    _LOCK_FILE.write_text(str(os.getpid()))
    atexit.register(_cleanup_lockfile)


def _cleanup_lockfile():
    """Remove the PID lock file when the process exits cleanly."""
    try:
        _LOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass


# ── File index ─────────────────────────────────────────────────────────────────

import gzip
import struct
import time as _time


class FileIndex:
    """
    In-memory index of all files under the shared root directory.

    Supports fast substring search, gzip-compressed on-disk caching,
    incremental offline-diff updates, and live add/remove notifications.
    A background thread periodically flushes dirty state back to disk.
    """

    CACHE_FILENAME = ".netshare_index.cache"

    def __init__(self):
        self._lock       = threading.RLock()
        self._entries: list  = []
        self._names_lc: list = []
        self.ready       = False
        self.total       = 0
        self._built_at   = 0.0
        self._dirty      = False
        self._flush_thread: threading.Thread | None = None
        self._flush_stop = threading.Event()

    @staticmethod
    def _cache_path(root):
        """Return the path to the gzip cache file for the given root directory."""
        return Path(root) / FileIndex.CACHE_FILENAME

    def build(self, root):
        """
        Start an asynchronous background build of the file index for *root*.

        Attempts to load a previously saved cache first; if available it runs
        a fast incremental diff instead of a full filesystem walk.
        """
        self.ready = False
        threading.Thread(target=self._build_thread, args=(Path(root),), daemon=True).start()

    def _build_thread(self, root):
        """Worker thread: load cache + diff, or fall back to a full scan."""
        if self._try_load_cache(root):
            self._apply_offline_diff(root)
            self._save_cache(root)
            return
        self._scan(root)
        self._save_cache(root)

    def _try_load_cache(self, root):
        """
        Attempt to deserialize the gzip cache for *root*.

        Returns True if the cache was loaded successfully, False otherwise
        (missing file, root mismatch, or parse error).
        """
        cache_file = self._cache_path(root)
        if not cache_file.exists():
            return False
        try:
            t0 = _time.monotonic()
            _emit("INDEX  loading cache...", "dim")
            with gzip.open(cache_file, "rb") as f:
                data = json.loads(f.read().decode("utf-8"))
            if data.get("root") != str(root):
                _emit("INDEX  cache mismatch — full scan needed", "dim")
                return False
            entries  = data["entries"]
            names_lc = [e["name"].lower() for e in entries]
            with self._lock:
                self._entries  = entries
                self._names_lc = names_lc
                self._built_at = data.get("built_at", 0.0)
                self.total     = len(entries)
                self.ready     = True
            _emit(f"INDEX  cache loaded — {self.total:,} files  [{_time.monotonic()-t0:.1f}s]", "dim")
            return True
        except Exception as e:
            _emit(f"INDEX  cache load failed ({e}) — full scan", "dim")
            return False

    def _apply_offline_diff(self, root):
        """
        Reconcile the cached index against the current filesystem state.

        Walks the directory tree and compares each file against the cached
        metadata. Adds new files, updates modified ones, and removes deleted
        ones without performing a full rescan.
        """
        _emit("INDEX  checking for offline changes...", "dim")
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
                    if fname.startswith("."): continue
                    fpath = base / fname
                    try:
                        stat = fpath.stat()
                        rel  = "/" + str(fpath.relative_to(root)).replace("\\", "/")
                        rel  = rel.encode("utf-8", errors="replace").decode("utf-8")
                        mtime_str = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                        on_disk.add(rel)
                        if rel not in cache_map:
                            fc = fname.encode("utf-8", errors="replace").decode("utf-8")
                            entry = {"name": fc, "path": rel, "is_dir": False,
                                     "size": stat.st_size, "modified": mtime_str}
                            with self._lock:
                                self._entries.append(entry)
                                self._names_lc.append(fc.lower())
                                self.total += 1
                            added += 1
                        elif cache_map[rel] != mtime_str:
                            fc = fname.encode("utf-8", errors="replace").decode("utf-8")
                            entry = {"name": fc, "path": rel, "is_dir": False,
                                     "size": stat.st_size, "modified": mtime_str}
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
            _emit(f"INDEX  diff walk error: {e}", "error")
        removed_paths = set(cache_map.keys()) - on_disk
        for rel in removed_paths:
            self.remove_file(rel)
        removed = len(removed_paths)
        elapsed = _time.monotonic() - t0
        if added or updated or removed:
            _emit(f"INDEX  diff done  +{added}  ~{updated}  -{removed}  [{elapsed:.1f}s]", "ok")
        else:
            _emit(f"INDEX  diff done  no changes  [{elapsed:.1f}s]", "dim")
        _emit(f"INDEX  ready — {self.total:,} files", "ok")

    def _save_cache(self, root):
        """
        Serialize the current index to a gzip-compressed JSON cache file.

        Writes to a temporary file first and then atomically replaces the
        cache file to avoid corruption on crash.
        """
        cache_file = self._cache_path(root)
        try:
            _emit("INDEX  saving cache...", "dim")
            with self._lock:
                entries = list(self._entries)
            payload = json.dumps({"root": str(root), "built_at": _time.time(),
                                  "entries": entries}, ensure_ascii=True).encode("utf-8")
            tmp = cache_file.with_suffix(".tmp")
            with gzip.open(tmp, "wb", compresslevel=1) as f:
                f.write(payload)
            tmp.replace(cache_file)
            size_mb = cache_file.stat().st_size / 1_048_576
            _emit(f"INDEX  cache saved  ({size_mb:.1f} MB)", "dim")
        except Exception as e:
            _emit(f"INDEX  cache save failed: {e}", "error")

    def _scan(self, root):
        """
        Perform a full recursive filesystem walk to populate the index from scratch.

        Hidden files and directories (names starting with '.') are skipped.
        Progress is logged every 50 000 files.
        """
        _emit("INDEX  scanning... (first run — will be cached)", "dim")
        entries = []
        names_lc = []
        count = 0
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                base = Path(dirpath)
                for fname in filenames:
                    if fname.startswith("."): continue
                    fpath = base / fname
                    try:
                        stat = fpath.stat()
                        rel  = str(fpath.relative_to(root)).replace("\\", "/")
                        fname = fname.encode("utf-8", errors="replace").decode("utf-8")
                        rel   = rel.encode("utf-8", errors="replace").decode("utf-8")
                        entry = {"name": fname, "path": f"/{rel}", "is_dir": False,
                                 "size": stat.st_size,
                                 "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")}
                        entries.append(entry)
                        names_lc.append(fname.lower())
                        count += 1
                        if count % 50_000 == 0:
                            _emit(f"INDEX  {count:,} files...", "dim")
                    except (PermissionError, OSError):
                        pass
        except Exception as e:
            _emit(f"INDEX  scan error: {e}", "error")
        with self._lock:
            self._entries  = entries
            self._names_lc = names_lc
            self.total     = count
            self.ready     = True
        _emit(f"INDEX  ready — {count:,} files", "ok")

    _TYPE_EXTENSIONS = {
        "image":    {"jpg","jpeg","png","gif","webp","bmp","tiff","tif","svg","heic","heif","avif","raw","cr2","nef","arw"},
        "video":    {"mp4","mkv","avi","mov","wmv","flv","webm","m4v","mpg","mpeg","3gp","ts","mts","m2ts","vob","ogv","rm","rmvb"},
        "audio":    {"mp3","flac","aac","wav","ogg","opus","m4a","wma","aiff","aif","alac","ape","mka","mid","midi"},
        "document": {"pdf","doc","docx","xls","xlsx","ppt","pptx","odt","ods","odp","txt","rtf","csv","md","epub","mobi","azw","djvu","pages","numbers","key"},
        "archive":  {"zip","rar","7z","tar","gz","bz2","xz","zst","cab","iso","dmg","pkg","deb","rpm"},
    }

    @classmethod
    def _get_file_category(cls, filename: str) -> str:
        """Return the broad category ('image', 'video', 'audio', etc.) for a filename based on its extension."""
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        for category, exts in cls._TYPE_EXTENSIONS.items():
            if ext in exts: return category
        return "other"

    def search(self, query, limit=50, offset=0, file_type="all"):
        """
        Perform a case-insensitive substring search against the index.

        Args:
            query: The search string.
            limit: Maximum number of results to return (capped at 200).
            offset: Number of results to skip for pagination.
            file_type: Optional category filter ('image', 'video', 'audio',
                       'document', 'archive', or 'all').

        Returns:
            A dict with keys 'items', 'total', 'offset', and 'has_more'.
        """
        q = query.strip().lower()
        if not q:
            return {"items": [], "total": 0, "offset": offset, "has_more": False}
        filter_type = file_type.lower() if file_type else "all"
        with self._lock:
            if filter_type == "all":
                matched = [self._entries[i] for i, name in enumerate(self._names_lc) if q in name]
            else:
                matched = [self._entries[i] for i, name in enumerate(self._names_lc)
                           if q in name and self._get_file_category(self._entries[i]["name"]) == filter_type]
        total = len(matched)
        return {"items": matched[offset:offset+limit], "total": total,
                "offset": offset, "has_more": (offset + limit) < total}

    def add_file(self, path, root):
        """
        Add or update a single file entry in the index.

        If the file's relative path is already present, its metadata is
        updated in-place. Hidden files are silently ignored.
        """
        if not path.is_file() or path.name.startswith("."): return
        try:
            stat  = path.stat()
            rel   = str(path.relative_to(root)).replace("\\", "/")
            entry = {"name": path.name, "path": f"/{rel}", "is_dir": False,
                     "size": stat.st_size,
                     "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")}
            lc = path.name.lower()
            with self._lock:
                for i, e in enumerate(self._entries):
                    if e["path"] == entry["path"]:
                        self._entries[i]  = entry
                        self._names_lc[i] = lc
                        return
                self._entries.append(entry)
                self._names_lc.append(lc)
                self.total += 1
                self._dirty = True
        except (PermissionError, OSError):
            pass

    def remove_file(self, rel_path):
        """Remove a file entry from the index by its relative path."""
        with self._lock:
            for i, e in enumerate(self._entries):
                if e["path"] == rel_path:
                    self._entries.pop(i)
                    self._names_lc.pop(i)
                    self.total -= 1
                    self._dirty = True
                    return

    def invalidate_cache(self, root):
        """Delete the on-disk cache file for *root*, forcing a full rescan on next build."""
        try: self._cache_path(root).unlink(missing_ok=True)
        except Exception: pass

    def start_periodic_flush(self, root, interval: int = 300):
        """
        Start a background thread that saves the cache to disk every *interval* seconds
        if the index has been modified since the last flush.
        """
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
        """Signal the periodic flush thread to stop and wait for it to finish."""
        self._flush_stop.set()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=2)
        self._flush_thread = None

    def flush_if_dirty(self, root):
        """Immediately save the cache to disk if there are unsaved changes."""
        if self._dirty and self.ready:
            self._save_cache(root)
            self._dirty = False

    def clear(self):
        """Reset the index to an empty, not-ready state and stop the flush thread."""
        self.stop_periodic_flush()
        with self._lock:
            self._entries  = []
            self._names_lc = []
            self.total     = 0
            self.ready     = False
            self._dirty    = False


_file_index = FileIndex()


# ── Directory watcher ──────────────────────────────────────────────────────────

_dir_observer = None


class _IndexEventHandler(FileSystemEventHandler if HAS_WATCHDOG else object):
    """
    Watchdog event handler that keeps the file index and WebSocket clients
    in sync with live filesystem changes.

    Handles file/directory creation, deletion, move, and modification events.
    Each event also broadcasts a JSON notification to all connected WebSocket clients.
    """

    def __init__(self, root: Path):
        if HAS_WATCHDOG: super().__init__()
        self._root = root

    def _rel(self, abs_path):
        """Convert an absolute filesystem path to a root-relative URL path."""
        try: return "/" + str(Path(abs_path).relative_to(self._root)).replace("\\", "/")
        except ValueError: return abs_path

    def _broadcast(self, payload):
        """Send a JSON payload to all connected WebSocket clients (thread-safe)."""
        if _ws_manager: _ws_manager.broadcast_threadsafe(json.dumps(payload))

    def on_created(self, event):
        """Handle a new file or directory being created under the watched root."""
        path = Path(event.src_path); rel = self._rel(event.src_path)
        if event.is_directory:
            _emit(f"WATCH  dir  added   {rel}", "dim"); self._broadcast({"type": "dir_added", "path": rel})
        else:
            if path.name.startswith("."): return
            _file_index.add_file(path, self._root)
            _emit(f"WATCH  file added   {rel}", "dim"); self._broadcast({"type": "file_added", "path": rel})

    def on_deleted(self, event):
        """Handle a file or directory being deleted from under the watched root."""
        rel = self._rel(event.src_path)
        if event.is_directory:
            prefix = rel.rstrip("/") + "/"
            with _file_index._lock:
                to_remove = [e["path"] for e in _file_index._entries if e["path"].startswith(prefix)]
            for p in to_remove: _file_index.remove_file(p)
            _emit(f"WATCH  dir  removed {rel}  ({len(to_remove)} files)", "dim")
            self._broadcast({"type": "dir_removed", "path": rel, "files_removed": len(to_remove)})
        else:
            _file_index.remove_file(rel)
            _emit(f"WATCH  file removed {rel}", "dim"); self._broadcast({"type": "file_removed", "path": rel})

    def on_moved(self, event):
        """Handle a file or directory being renamed or moved within the watched root."""
        src_rel = self._rel(event.src_path); dest_rel = self._rel(event.dest_path)
        dest_path = Path(event.dest_path)
        if event.is_directory:
            src_p = src_rel.rstrip("/") + "/"; dest_p = dest_rel.rstrip("/") + "/"
            with _file_index._lock:
                for entry in _file_index._entries:
                    if entry["path"].startswith(src_p):
                        entry["path"] = dest_p + entry["path"][len(src_p):]
            _emit(f"WATCH  dir  moved   {src_rel} → {dest_rel}", "dim")
            self._broadcast({"type": "dir_moved", "src": src_rel, "dest": dest_rel})
        else:
            _file_index.remove_file(src_rel)
            if not dest_path.name.startswith("."): _file_index.add_file(dest_path, self._root)
            _emit(f"WATCH  file moved   {src_rel} → {dest_rel}", "dim")
            self._broadcast({"type": "file_moved", "src": src_rel, "dest": dest_rel})

    def on_modified(self, event):
        """Handle a file being modified (content or metadata changed)."""
        if event.is_directory: return
        path = Path(event.src_path)
        if path.name.startswith("."): return
        _file_index.add_file(path, self._root)
        self._broadcast({"type": "file_modified", "path": self._rel(event.src_path)})


def _start_watcher(root: Path):
    """
    Start a watchdog observer on *root* (recursive).

    Stops any previously running observer before creating a new one.
    Does nothing if watchdog is not installed.
    """
    global _dir_observer
    if not HAS_WATCHDOG:
        _emit("WATCH  watchdog not installed — live updates disabled", "dim")
        _emit("→  pip install watchdog", "dim"); return
    _stop_watcher()
    handler = _IndexEventHandler(root)
    observer = Observer()
    observer.schedule(handler, str(root), recursive=True)
    observer.daemon = True; observer.start()
    _dir_observer = observer
    _emit(f"WATCH  watching {root}", "ok")


def _stop_watcher():
    """Stop the currently running watchdog observer, if any."""
    global _dir_observer
    if _dir_observer is not None:
        try: _dir_observer.stop(); _dir_observer.join(timeout=2)
        except Exception: pass
        _dir_observer = None


# ── WebSocket manager ──────────────────────────────────────────────────────────

_ws_manager = None


class WebSocketManager:
    """
    Manages the set of active WebSocket client connections and provides
    thread-safe broadcast and graceful shutdown capabilities.
    """

    def __init__(self):
        self._clients: set = set()
        self._loop = None
        self._lock = threading.Lock()
        self._stop_event: asyncio.Event | None = None

    def set_loop(self, loop):
        """Attach the asyncio event loop used by the WebSocket server thread."""
        self._loop = loop; self._stop_event = asyncio.Event()

    def add_client(self, ws):
        """Register a new WebSocket connection and log the connection count."""
        with self._lock: self._clients.add(ws)
        _emit(f"WS  +  client connected  ({len(self._clients)} total)")

    def remove_client(self, ws):
        """Unregister a disconnected WebSocket client and log the remaining count."""
        with self._lock: self._clients.discard(ws)
        _emit(f"WS  −  client disconnected  ({len(self._clients)} remaining)")

    def client_count(self):
        """Return the number of currently connected WebSocket clients."""
        with self._lock: return len(self._clients)

    async def _broadcast(self, message: str):
        """
        Send *message* to all connected clients.

        Dead connections are silently removed from the client set.
        """
        with self._lock: targets = set(self._clients)
        if not targets: return
        dead = set()
        for ws in targets:
            try: await ws.send(message)
            except Exception: dead.add(ws)
        if dead:
            with self._lock: self._clients -= dead

    def broadcast_threadsafe(self, message: str):
        """Schedule a broadcast from any thread using the server's asyncio loop."""
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._broadcast(message), self._loop)

    def notify_file_change(self, path: str):
        """Broadcast a 'file_change' event for the given relative *path*."""
        self.broadcast_threadsafe(json.dumps({"type": "file_change", "path": path}))

    def notify_server_stopping(self):
        """
        Broadcast a 'server_stopping' event and gracefully shut down the
        WebSocket server. Blocks until the shutdown sequence completes (max 3 s).
        """
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._shutdown_sequence(), self._loop).result(timeout=3)

    async def _shutdown_sequence(self):
        """Send the shutdown notice, wait briefly for clients to react, then set the stop event."""
        await self._broadcast(json.dumps({"type": "server_stopping"}))
        await asyncio.sleep(0.15)
        if self._stop_event: self._stop_event.set()


async def _ws_handler(websocket):
    """
    Handle a single WebSocket client connection lifecycle.

    On connect, the client receives a 'welcome' message with server metadata.
    The handler responds to 'ping' messages with 'pong' and cleans up on disconnect.
    """
    global _ws_manager
    if _ws_manager is None:
        await websocket.close(1001, "Manager not initialized"); return
    _ws_manager.add_client(websocket)
    await websocket.send(json.dumps({"type": "welcome", "name": SERVER_NAME,
                                     "version": VERSION, "root": str(ROOT_DIR)}))
    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
                if msg.get("type") == "ping":
                    await websocket.send(json.dumps({"type": "pong"}))
            except Exception: pass
    except Exception: pass
    finally: _ws_manager.remove_client(websocket)


def _run_ws_server(host: str, port: int, manager: WebSocketManager):
    """
    Run the asyncio WebSocket server in a dedicated thread.

    Creates a new event loop, starts the server on *host*:*port*, and blocks
    until the manager's stop event is set (triggered by _shutdown_sequence).
    """
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop); manager.set_loop(loop)
    async def _serve():
        async with websockets.serve(_ws_handler, host, port, reuse_address=True):
            _emit(f"WS   :{port}   running")
            await manager._stop_event.wait()
    try: loop.run_until_complete(_serve())
    except Exception as e: _emit(f"WS   stopped  {e}")
    finally: loop.close()


# ── IP / path helpers ──────────────────────────────────────────────────────────

def get_local_ips():
    """
    Return a list of non-loopback IPv4 addresses for this machine.

    Uses two methods: hostname resolution and a UDP connect trick (no packet
    is actually sent). Falls back to ['127.0.0.1'] if nothing is found.
    """
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception: pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]
        if ip not in ips: ips.append(ip)
        s.close()
    except Exception: pass
    return ips or ["127.0.0.1"]


def safe_path(rel_path: str):
    """
    Resolve a client-supplied relative path to an absolute Path under ROOT_DIR.

    Returns None if the resolved path would escape the root directory
    (path traversal protection).
    """
    clean = unquote(rel_path).lstrip("/\\")
    resolved = (ROOT_DIR / clean).resolve()
    try: resolved.relative_to(ROOT_DIR.resolve()); return resolved
    except ValueError: return None


def file_info(path: Path, base: Path):
    """
    Build a JSON-serializable metadata dict for a single file or directory.

    Returns keys: name, path (root-relative), is_dir, size, modified.
    """
    rel  = str(path.relative_to(base)).replace("\\", "/")
    stat = path.stat()
    return {"name": path.name, "path": f"/{rel}", "is_dir": path.is_dir(),
            "size": stat.st_size if path.is_file() else None,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")}


def _emit(msg: str, kind: str = "info"):
    """
    Post a log message to the shared queue and print it to stdout
    if no GUI log callback has been registered yet.
    """
    _log_queue.put((msg, kind))
    if not _log_callback: print(msg)


# ── Cover art extractor ────────────────────────────────────────────────────────

def extract_cover_from_mp3(file_path: Path):
    """
    Extract the embedded cover image from an MP3 file's ID3 tag (APIC frame).

    Supports ID3 v2.3 and v2.4 tag formats. Returns a (bytes, mime_type) tuple
    on success, or None if no embedded image is found or the file is not a
    valid ID3-tagged MP3.
    """
    try:
        with open(file_path, "rb") as f: header = f.read(10)
        if len(header) < 10 or header[:3] != b"ID3": return None
        id3_version = header[3]
        tag_size = ((header[6]&0x7F)<<21|(header[7]&0x7F)<<14|(header[8]&0x7F)<<7|(header[9]&0x7F))
        with open(file_path, "rb") as f:
            f.seek(10); tag_data = f.read(tag_size)
        i = 0
        while i + 10 <= len(tag_data):
            frame_id = tag_data[i:i+4].decode("latin-1", errors="ignore")
            if frame_id == "\x00\x00\x00\x00": break
            if id3_version >= 4:
                frame_size = ((tag_data[i+4]&0x7F)<<21|(tag_data[i+5]&0x7F)<<14|
                              (tag_data[i+6]&0x7F)<<7|(tag_data[i+7]&0x7F))
            else:
                frame_size = struct.unpack(">I", tag_data[i+4:i+8])[0]
            i += 10
            if frame_size <= 0 or i + frame_size > len(tag_data): break
            if frame_id == "APIC":
                frame = tag_data[i:i+frame_size]
                try:
                    encoding = frame[0]; mime_end = frame.index(b"\x00", 1)
                    mime = frame[1:mime_end].decode("latin-1", errors="ignore").strip()
                    rest = frame[mime_end+1:]
                    if encoding in (1, 2):
                        desc_end = 1
                        while desc_end+1 < len(rest):
                            if rest[desc_end]==0 and rest[desc_end+1]==0:
                                desc_end += 2; break
                            desc_end += 2
                    else:
                        desc_end = rest.index(b"\x00", 1) + 1
                    img_data = rest[desc_end:]
                    if not mime or "/" not in mime: mime = "image/jpeg"
                    if len(img_data) > 0: return img_data, mime
                except Exception: pass
            i += frame_size
    except Exception: pass
    return None


# ── HTTP Handler ───────────────────────────────────────────────────────────────

class NetShareHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the NetShare file server.

    Exposes the following endpoints (all require the X-Password header when a
    server password is configured, except /ping which is always public):

    GET /ping        — Health check; returns server metadata.
    GET /list        — List the contents of a directory (?path=/).
    GET /search      — Search the file index (?q=query&limit=50&offset=0&type=all).
    GET /file        — Download or stream a file (?path=/rel/path).
    GET /thumbnail   — Serve a resized JPEG thumbnail (?path=...&w=300&h=300).
    GET /art         — Return embedded MP3 cover art (?path=/rel/path.mp3).
    OPTIONS *        — CORS preflight response.
    """

    def log_message(self, fmt, *args): pass

    def log_request(self, code="-", size="-"):
        """Log each HTTP request with its method, path, status code, and client IP."""
        status = str(code)
        kind = "error" if status[0] in ("4","5") else "info"
        _emit(f"{self.command:<8} {self.path}  →  {code}  [{self.client_address[0]}]", kind)

    def log_error(self, fmt, *args): _emit(f"ERROR  {fmt % args}", "error")

    def send_json(self, data, status=200):
        """Serialize *data* to JSON and write a complete HTTP response."""
        try:
            body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers(); self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass

    def send_error_json(self, msg, status=400):
        """Send a JSON error response with the given message and HTTP status code."""
        try: self.send_json({"error": msg}, status)
        except (BrokenPipeError, ConnectionResetError): pass

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def _check_password(self):
        """Return True if no password is set, or if the request carries the correct X-Password header."""
        if not SERVER_PASSWORD: return True
        return self.headers.get("X-Password", "") == SERVER_PASSWORD

    def do_GET(self):
        """Route incoming GET requests to the appropriate endpoint handler."""
        parsed = urlparse(self.path); endpoint = parsed.path.rstrip("/"); params = parse_qs(parsed.query)

        if endpoint == "/ping":
            ws_port = None
            if _ws_manager is not None:
                try: ws_port = int(self.server.server_address[1]) + 1
                except Exception: pass
            self.send_json({"name": SERVER_NAME, "version": VERSION, "root": str(ROOT_DIR),
                            "ws_port": ws_port, "index_ready": _file_index.ready,
                            "index_total": _file_index.total, "requires_password": bool(SERVER_PASSWORD)})
            return

        if not self._check_password():
            self.send_error_json("Unauthorized", 401); return

        if endpoint == "/list":
            rel = params.get("path", ["/"])[0]
            target = ROOT_DIR if rel in ("/","") else safe_path(rel)
            if target is None: return self.send_error_json("Invalid path", 403)
            if not target or not target.exists(): return self.send_error_json("Directory not found", 404)
            if not target.is_dir(): return self.send_error_json("Not a directory", 400)
            try:
                items = []
                for entry in sorted(target.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
                    try:
                        if entry.name.startswith("."): continue
                        items.append(file_info(entry, ROOT_DIR))
                    except (PermissionError, OSError): pass
                self.send_json(items)
            except PermissionError: self.send_error_json("Permission denied", 403)

        elif endpoint == "/search":
            if params.get("invalidate"):
                _file_index.clear(); _file_index.invalidate_cache(ROOT_DIR); _file_index.build(ROOT_DIR)
                return self.send_json({"ok": True, "message": "cache invalidated, reindexing"})
            if params.get("ready"):
                return self.send_json({"ready": _file_index.ready, "total": _file_index.total})
            query = params.get("q", [""])[0]
            if not query.strip():
                return self.send_json({"items": [], "total": 0, "offset": 0, "has_more": False})
            try: limit = min(int(params.get("limit", ["50"])[0]), 200)
            except (ValueError, IndexError): limit = 50
            try: offset = max(int(params.get("offset", ["0"])[0]), 0)
            except (ValueError, IndexError): offset = 0
            file_type = params.get("type", ["all"])[0]
            self.send_json(_file_index.search(query, limit=limit, offset=offset, file_type=file_type))

        elif endpoint == "/file":
            rel = params.get("path", [""])[0]
            if not rel: return self.send_error_json("Missing 'path' parameter", 400)
            target = safe_path(rel)
            if target is None: return self.send_error_json("Invalid path", 403)
            if not target or not target.exists(): return self.send_error_json("File not found", 404)
            if not target.is_file(): return self.send_error_json("Not a file", 400)
            try:
                file_size = target.stat().st_size
                mime, _ = mimetypes.guess_type(str(target)); mime = mime or "application/octet-stream"
                range_hdr = self.headers.get("Range")
                if range_hdr: self._serve_range(target, file_size, mime, range_hdr)
                else: self._serve_full(target, file_size, mime)
            except PermissionError: self.send_error_json("Permission denied", 403)
            except Exception as e: self.send_error_json(f"Server error: {e}", 500)

        elif endpoint == "/thumbnail":
            rel = params.get("path", [""])[0]
            if not rel: return self.send_error_json("Missing 'path' parameter", 400)
            target = safe_path(rel)
            if target is None: return self.send_error_json("Invalid path", 403)
            if not target or not target.exists() or not target.is_file():
                return self.send_error_json("File not found", 404)
            file_size = target.stat().st_size
            if file_size > 50*1024*1024: return self.send_error_json("File too large for thumbnail", 413)
            if not HAS_PIL:
                try:
                    mime, _ = mimetypes.guess_type(str(target))
                    self._serve_full(target, file_size, mime or "application/octet-stream")
                except Exception as e: self.send_error_json(f"Server error: {e}", 500)
                return
            try: max_w = min(int(params.get("w",["300"])[0]),300); max_h = min(int(params.get("h",["300"])[0]),300)
            except (ValueError, IndexError): max_w, max_h = 300, 300
            try:
                with PilImage.open(target) as img:
                    if img.width>10000 or img.height>10000: return self.send_error_json("Image too large for thumbnail",413)
                    if img.mode not in ("RGB","L"): img = img.convert("RGB")
                    img.thumbnail((max_w,max_h), PilImage.LANCZOS)
                    buf = BytesIO(); img.save(buf, format="JPEG", quality=75, optimize=True); data = buf.getvalue()
                    if len(data)>500*1024:
                        img.thumbnail((100,100), PilImage.LANCZOS); buf = BytesIO()
                        img.save(buf, format="JPEG", quality=60); data = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type","image/jpeg"); self.send_header("Content-Length",str(len(data)))
                self.send_header("Cache-Control","max-age=86400"); self.send_header("Access-Control-Allow-Origin","*")
                self.end_headers(); self.wfile.write(data)
            except Exception as e: self.send_error_json(f"Thumbnail error: {e}", 500)

        elif endpoint == "/art":
            rel = params.get("path", [""])[0]
            if not rel: return self.send_error_json("Missing 'path' parameter", 400)
            target = safe_path(rel)
            if target is None: return self.send_error_json("Invalid path", 403)
            if not target or not target.exists() or not target.is_file():
                return self.send_error_json("File not found", 404)
            result = extract_cover_from_mp3(target)
            if result:
                img_data, mime = result
                try:
                    self.send_response(200); self.send_header("Content-Type", mime)
                    self.send_header("Content-Length", str(len(img_data)))
                    self.send_header("Cache-Control","max-age=86400"); self.send_header("Access-Control-Allow-Origin","*")
                    self.end_headers(); self.wfile.write(img_data)
                except (BrokenPipeError, ConnectionResetError): pass
            else:
                self.send_response(404); self.send_header("Content-Length","0"); self.end_headers()
        else:
            self.send_error_json("Unknown endpoint", 404)

    _CHUNK = 8 * 1024 * 1024

    def _serve_full(self, path, size, mime):
        """
        Send the entire file as a single HTTP 200 response.

        Uses an 8 MB read chunk and disables Nagle's algorithm (TCP_NODELAY)
        so each chunk is flushed to the network immediately, minimizing
        CPU overhead for large files over a LAN.
        """
        self.send_response(200); self.send_header("Content-Type", mime)
        self.send_header("Content-Length", size); self.send_header("Accept-Ranges", "bytes")
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Content-Disposition", f'inline; filename="{path.name}"')
        try: self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception: pass
        self.end_headers()
        with open(path, "rb") as f:
            while chunk := f.read(self._CHUNK):
                try: self.wfile.write(chunk)
                except BrokenPipeError: break

    def _serve_range(self, path, size, mime, range_header):
        """
        Serve a byte-range request (HTTP 206 Partial Content).

        Enables seeking and resumable downloads. Falls back to a full response
        if the Range header cannot be parsed. TCP_NODELAY is enabled for the
        same reason as in _serve_full.
        """
        try:
            byte_range = range_header.replace("bytes=",""); parts = byte_range.split("-")
            start = int(parts[0]) if parts[0] else 0; end = int(parts[1]) if parts[1] else size-1
            end = min(end, size-1); length = end - start + 1
            self.send_response(206); self.send_header("Content-Type", mime)
            self.send_header("Content-Length", length); self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("Accept-Ranges","bytes"); self.send_header("Access-Control-Allow-Origin","*")
            try: self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception: pass
            self.end_headers()
            with open(path, "rb") as f:
                f.seek(start); remaining = length
                while remaining > 0:
                    chunk = f.read(min(self._CHUNK, remaining))
                    if not chunk: break
                    try: self.wfile.write(chunk)
                    except BrokenPipeError: break
                    remaining -= len(chunk)
        except (ValueError, IndexError): self._serve_full(path, size, mime)
        except (BrokenPipeError, ConnectionResetError): pass


# ── GUI ────────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    """
    Main application window for the NetShare Player server launcher.

    Provides a minimal, monochrome GUI for:
    - Selecting the folder to share.
    - Configuring the HTTP port, server name, and optional password.
    - Starting and stopping the HTTP + WebSocket server.
    - Displaying local network addresses with one-click copy and QR code generation.
    - Viewing a live server log.
    - Toggling between dark and light themes.
    """

    def __init__(self):
        super().__init__()
        self.title("NETSHARE PLAYER")

        self._dark_mode = True
        _theme.update(_DARK)

        try:
            raw_scale = self.tk.call("tk", "scaling")
            self._ui_scale = max(1.0, raw_scale / 1.3333)
        except Exception:
            self._ui_scale = 1.0

        if PLATFORM == "linux":
            for ev in ("GDK_SCALE", "QT_SCALE_FACTOR"):
                try:
                    v = float(os.environ.get(ev, ""))
                    if v > self._ui_scale: self._ui_scale = v
                except (ValueError, TypeError): pass

        self._ui_scale = min(max(self._ui_scale, 1.0), 3.0)
        self._win_w = int(480 * self._ui_scale)
        self._win_h = int(700 * self._ui_scale)

        self.configure(bg=BG())
        self.resizable(False, True)
        self.minsize(self._win_w, int(500 * self._ui_scale))
        self.maxsize(self._win_w, int(1000 * self._ui_scale))

        self._server    = None
        self._thread    = None
        self._running   = False
        self._ws_thread = None

        self._selected_folder = tk.StringVar(value="")
        self._port_var        = tk.StringVar(value=str(DEFAULT_PORT))
        self._name_var        = tk.StringVar(value=socket.gethostname())
        self._password_var    = tk.StringVar(value="")
        self._folder_history: list[str] = []

        icon_path = Path(__file__).parent / "favicon.ico"
        if icon_path.exists():
            try:
                self.iconbitmap(str(icon_path))
            except Exception:
                pass

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.update_idletasks()
        w = self.winfo_width(); h = self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2; y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{self._win_w}x{self._win_h}+{x}+{y}")

    # ── Scale helpers ──────────────────────────────────────────────────────────

    def _s(self, v):
        """Scale a pixel value by the current DPI scale factor."""
        return int(v * self._ui_scale)

    def _fs(self, v):
        """Scale a font size by the DPI factor (no scaling on macOS where Tk handles it)."""
        return v if PLATFORM == "mac" else max(1, int(v * self._ui_scale))

    # ── Theme toggle ───────────────────────────────────────────────────────────

    def _toggle_theme(self):
        """Switch between dark and light themes and repaint the entire widget tree."""
        self._dark_mode = not self._dark_mode
        _theme.update(_DARK if self._dark_mode else _LIGHT)
        self._theme_btn.configure(
            text="☀" if self._dark_mode else "☾",
            bg=_theme["TOGGLE_BG"], fg=_theme["TOGGLE_FG"],
            activebackground=_theme["TOGGLE_BG"], activeforeground=FG(),
        )
        self.configure(bg=BG())
        self._repaint_all(self)

    def _repaint_all(self, widget):
        """Recursively repaint *widget* and all its descendants."""
        self._repaint_widget(widget)
        for child in widget.winfo_children():
            self._repaint_all(child)

    def _swap(self, colour: str) -> str:
        """
        Translate a hex colour from the palette we just left to the palette we just entered.

        Returns the original colour unchanged if no match is found.
        """
        old = _LIGHT if self._dark_mode else _DARK
        new = _DARK  if self._dark_mode else _LIGHT
        c = colour.lower()
        for key, val in old.items():
            if c == val.lower() and key in new:
                return new[key]
        return colour

    def _recolour(self, widget, option: str):
        """Update a single colour option on *widget* using the current theme palette."""
        try:
            cur = widget.cget(option)
            if isinstance(cur, str) and cur.startswith("#"):
                nw = self._swap(cur)
                if nw != cur: widget.configure(**{option: nw})
        except Exception: pass

    def _repaint_widget(self, w):
        """
        Update the theme colours for a single widget based on its Tk class.

        Handles Frame, Label, Button, Canvas, Entry, Text, and Scrollbar.
        Also refreshes the colour tags on log Text widgets.
        """
        cls = w.winfo_class()
        try:
            if cls in ("Frame", "Label", "Button", "Canvas"):
                self._recolour(w, "bg")
            if cls in ("Label", "Button"):
                self._recolour(w, "fg")
            if cls == "Button":
                self._recolour(w, "activebackground")
                self._recolour(w, "activeforeground")
            if cls == "Entry":
                for opt in ("bg","fg","insertbackground","highlightbackground"):
                    self._recolour(w, opt)
            if cls == "Text":
                self._recolour(w, "bg"); self._recolour(w, "fg")
                try:
                    w.tag_configure("info",  foreground=FG2())
                    w.tag_configure("ok",    foreground=FG())
                    w.tag_configure("error", foreground=DANGER())
                    w.tag_configure("dim",   foreground=FG3())
                    w.tag_configure("ts",    foreground=FG3())
                except Exception: pass
            if cls == "Scrollbar":
                w.configure(bg=BG(), troughcolor=SURFACE(), activebackground=FG3())
        except Exception: pass

    # ── Build UI ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        """
        Construct the complete UI layout.

        The window body lives inside a scrollable Canvas so that the log
        and address sections remain visible on small screens. Mouse wheel
        scrolling is bound globally.
        """
        outer = tk.Frame(self, bg=BG())
        outer.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(outer, bg=BG(), highlightthickness=0, bd=0)
        self._scrollbar = tk.Scrollbar(outer, orient="vertical", command=self._canvas.yview,
                                       bg=BG(), troughcolor=SURFACE(), activebackground=FG3())
        self._canvas.configure(yscrollcommand=self._scrollbar.set)
        self._scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._body = tk.Frame(self._canvas, bg=BG())
        self._body_win_id = self._canvas.create_window((0,0), window=self._body, anchor="nw")

        def _on_canvas_resize(e):
            self._canvas.itemconfig(self._body_win_id, width=e.width)
        self._canvas.bind("<Configure>", _on_canvas_resize)

        def _on_body_resize(e):
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
            bb = self._canvas.bbox("all")
            if bb:
                if bb[3] <= self._canvas.winfo_height(): self._scrollbar.pack_forget()
                else: self._scrollbar.pack(side="right", fill="y")
        self._body.bind("<Configure>", _on_body_resize)

        def _on_mousewheel(e):
            if e.num == 4: self._canvas.yview_scroll(-1, "units")
            elif e.num == 5: self._canvas.yview_scroll(1, "units")
            else:
                units = int(-1*(e.delta/120)) if PLATFORM=="windows" else int(-1*e.delta)
                self._canvas.yview_scroll(units, "units")
        self._canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self._canvas.bind_all("<Button-4>",   _on_mousewheel)
        self._canvas.bind_all("<Button-5>",   _on_mousewheel)

        header = tk.Frame(self._body, bg=BG())
        header.pack(fill="x", padx=self._s(24), pady=(self._s(28), 0))

        logo_size = self._s(32)
        logo_cv = tk.Canvas(header, width=logo_size, height=logo_size, bg=BG(), highlightthickness=0)
        logo_cv.pack(side="left", padx=(0, self._s(12)))
        logo_cv.create_rectangle(0, 0, logo_size, logo_size, fill=FG(), outline="")
        lw = max(2, self._s(3)); m = self._s(8); e = logo_size - m
        logo_cv.create_line(m, e, m, m, fill=BG(), width=lw, capstyle="projecting")
        logo_cv.create_line(m, m, e, e, fill=BG(), width=lw, capstyle="projecting")
        logo_cv.create_line(e, e, e, m, fill=BG(), width=lw, capstyle="projecting")

        title_frame = tk.Frame(header, bg=BG())
        title_frame.pack(side="left")
        tk.Label(title_frame, text="N E T S H A R E", font=(FONT_MONO, self._fs(14), "bold"),
                 fg=FG(), bg=BG()).pack(side="left")
        tk.Label(title_frame, text="  P L A Y E R", font=(FONT_MONO, self._fs(14)),
                 fg=FG2(), bg=BG()).pack(side="left")

        subheader = tk.Frame(self._body, bg=BG())
        subheader.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0))

        self._theme_btn = tk.Button(
            subheader,
            text="☀",
            font=(FONT_MONO, self._fs(11)),
            fg=_theme["TOGGLE_FG"],
            bg=_theme["TOGGLE_BG"],
            activebackground=_theme["TOGGLE_BG"],
            activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(4),
            command=self._toggle_theme,
        )
        self._theme_btn.pack(side="left")

        status_frame = tk.Frame(subheader, bg=BG())
        status_frame.pack(side="right")
        dot_size = self._s(8)
        self._status_canvas = tk.Canvas(status_frame, width=dot_size, height=dot_size,
                                        bg=BG(), highlightthickness=0)
        self._status_canvas.pack(side="left", padx=(0, self._s(6)))
        self._status_dot_id = self._status_canvas.create_rectangle(0, 0, dot_size, dot_size,
                                                                    fill=FG3(), outline="")
        self._status_lbl = tk.Label(status_frame, text="OFFLINE",
                                    font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=BG())
        self._status_lbl.pack(side="left")

        self._hairline()

        ver_frame = tk.Frame(self._body, bg=BG())
        ver_frame.pack(fill="x", padx=self._s(24), pady=(self._s(10), 0))
        tk.Label(ver_frame, text=f"V{VERSION}", font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left")
        tk.Label(ver_frame, text="MÉLO TECHNOLOGY", font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="right")

        self._section_label("DIRECTORY"); self._build_folder_section()
        self._section_label("CONFIG");    self._build_config_section()

        btn_outer = tk.Frame(self._body, bg=BG())
        btn_outer.pack(fill="x", padx=self._s(24), pady=(self._s(16), 0))
        self._toggle_btn = tk.Button(btn_outer, text="START SERVER",
                                     font=(FONT_MONO, self._fs(11), "bold"),
                                     fg=BG(), bg=FG(), activebackground=FG2(), activeforeground=BG(),
                                     relief="flat", bd=0, cursor="hand2", pady=self._s(14),
                                     command=self._toggle_server)
        self._toggle_btn.pack(fill="x")
        self._add_hover(self._toggle_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())

        self._section_label("ADDRESSES")
        self._addr_frame = tk.Frame(self._body, bg=BG())
        self._addr_frame.pack(fill="x", padx=self._s(24), pady=(0, self._s(6)))
        self._draw_offline_placeholder()

        self._section_label("LOG")
        log_outer = tk.Frame(self._body, bg=SURFACE(), highlightthickness=1, highlightbackground=BORDER())
        log_outer.pack(fill="x", padx=self._s(24), pady=(0, self._s(24)))
        self._log_text = tk.Text(log_outer, height=9, bg=SURFACE(), fg=FG2(),
                                 font=(FONT_MONO, self._fs(9)), relief="flat", bd=0,
                                 padx=self._s(12), pady=self._s(10), state="disabled",
                                 insertbackground=FG(), wrap="word", cursor="arrow")
        self._log_text.pack(fill="x")
        self._log_text.tag_configure("info",  foreground=FG2())
        self._log_text.tag_configure("ok",    foreground=FG())
        self._log_text.tag_configure("error", foreground=DANGER())
        self._log_text.tag_configure("dim",   foreground=FG3())
        self._log_text.tag_configure("ts",    foreground=FG3())

    def _hairline(self, padx=None, pady=None):
        """Draw a 1-pixel horizontal separator line."""
        if padx is None: padx = self._s(24)
        if pady is None: pady = (self._s(12), 0)
        tk.Frame(self._body, bg=BORDER(), height=1).pack(fill="x", padx=padx, pady=pady)

    def _section_label(self, text):
        """Render a section heading with a decorative horizontal rule to its right."""
        frame = tk.Frame(self._body, bg=BG())
        frame.pack(fill="x", padx=self._s(24), pady=(self._s(18), self._s(8)))
        tk.Label(frame, text=text, font=(FONT_MONO, self._fs(8), "bold"),
                 fg=FG3(), bg=BG()).pack(side="left")
        tk.Frame(frame, bg=BORDER(), height=1).pack(side="left", fill="x", expand=True,
                                                     padx=(self._s(10), 0), pady=(1, 0))

    def _build_folder_section(self):
        """
        Build the directory selector row.

        Includes a display label showing the current selection, a BROWSE button,
        and a row of quick-access buttons for recently used folders.
        """
        outer = tk.Frame(self._body, bg=BG())
        outer.pack(fill="x", padx=self._s(24), pady=(0, self._s(4)))
        self._folder_display = tk.Label(outer, text="NO FOLDER SELECTED",
                                        font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=SURFACE(),
                                        anchor="w", padx=self._s(12), pady=self._s(10), width=32,
                                        highlightthickness=1, highlightbackground=BORDER())
        self._folder_display.pack(side="left", fill="x", expand=True)
        browse_btn = tk.Button(outer, text="BROWSE", font=(FONT_MONO, self._fs(9), "bold"),
                               fg=FG(), bg=SURFACE2(), activebackground=FG(), activeforeground=BG(),
                               relief="flat", bd=0, cursor="hand2",
                               padx=self._s(14), pady=self._s(10),
                               highlightthickness=1, highlightbackground=BORDER(),
                               command=self._browse_folder)
        browse_btn.pack(side="right", padx=(self._s(6), 0))
        self._add_hover(browse_btn, SURFACE2(), FG(), text_normal=FG(), text_hover=BG())
        self._hist_outer = tk.Frame(self._body, bg=BG())
        self._hist_outer.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0))
        self._refresh_history()

    def _refresh_history(self):
        """Rebuild the recent-folders button row from the current history list."""
        for w in self._hist_outer.winfo_children(): w.destroy()
        if not self._folder_history: return
        tk.Label(self._hist_outer, text="RECENT", font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left", padx=(0, self._s(8)))
        for folder in reversed(self._folder_history[-MAX_HISTORY:]):
            name = Path(folder).name or folder
            btn = tk.Button(self._hist_outer, text=name[:14], font=(FONT_MONO, self._fs(8)),
                            fg=FG2(), bg=BG(), activebackground=SURFACE2(), activeforeground=FG(),
                            relief="flat", bd=0, cursor="hand2",
                            padx=self._s(8), pady=self._s(3),
                            highlightthickness=1, highlightbackground=BORDER(),
                            command=lambda f=folder: self._select_folder(f))
            btn.pack(side="left", padx=(0, self._s(4)))

    def _build_config_section(self):
        """
        Build the server configuration fields: PORT, NAME, and PASSWORD.

        Entry fields highlight their border on focus for visual feedback.
        """
        row = tk.Frame(self._body, bg=BG())
        row.pack(fill="x", padx=self._s(24), pady=(0, self._s(4)))

        tk.Label(row, text="PORT", font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left", padx=(0, self._s(6)))
        port_entry = tk.Entry(row, textvariable=self._port_var,
                              font=(FONT_MONO, self._fs(10)), fg=FG(), bg=SURFACE(),
                              insertbackground=FG(), relief="flat", bd=0, width=6,
                              highlightthickness=1, highlightbackground=BORDER())
        port_entry.pack(side="left", ipady=self._s(8), padx=(0, self._s(20)))
        port_entry.bind("<FocusIn>",  lambda e: port_entry.config(highlightbackground=FG()))
        port_entry.bind("<FocusOut>", lambda e: port_entry.config(highlightbackground=BORDER()))

        tk.Label(row, text="NAME", font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left", padx=(0, self._s(6)))
        name_entry = tk.Entry(row, textvariable=self._name_var,
                              font=(FONT_MONO, self._fs(10)), fg=FG(), bg=SURFACE(),
                              insertbackground=FG(), relief="flat", bd=0, width=18,
                              highlightthickness=1, highlightbackground=BORDER())
        name_entry.pack(side="left", ipady=self._s(8))
        name_entry.bind("<FocusIn>",  lambda e: name_entry.config(highlightbackground=FG()))
        name_entry.bind("<FocusOut>", lambda e: name_entry.config(highlightbackground=BORDER()))

        pw_row = tk.Frame(self._body, bg=BG())
        pw_row.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0))
        tk.Label(pw_row, text="PASSWORD", font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left", padx=(0, self._s(6)))
        self._pw_entry = tk.Entry(pw_row, textvariable=self._password_var,
                                  font=(FONT_MONO, self._fs(10)), fg=FG(), bg=SURFACE(),
                                  insertbackground=FG(), relief="flat", bd=0, width=20,
                                  highlightthickness=1, highlightbackground=BORDER(), show="•")
        self._pw_entry.pack(side="left", ipady=self._s(8), padx=(0, self._s(10)))
        self._pw_entry.bind("<FocusIn>",  lambda e: self._pw_entry.config(highlightbackground=FG()))
        self._pw_entry.bind("<FocusOut>", lambda e: self._pw_entry.config(highlightbackground=BORDER()))
        tk.Label(pw_row, text="(leave empty = no auth)", font=(FONT_MONO, self._fs(7)),
                 fg=FG3(), bg=BG()).pack(side="left")

    def _draw_offline_placeholder(self):
        """Show a placeholder message in the addresses section when the server is stopped."""
        for w in self._addr_frame.winfo_children(): w.destroy()
        tk.Label(self._addr_frame, text="—  start server to see addresses",
                 font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=BG()).pack(anchor="w")

    # ── Log drainer ────────────────────────────────────────────────────────────

    def _start_log_drainer(self):
        """Activate the periodic log queue drainer."""
        self._drainer_active = True; self._drain_log_queue()

    def _stop_log_drainer(self):
        """Deactivate the log queue drainer."""
        self._drainer_active = False

    def _drain_log_queue(self):
        """
        Pull all pending messages from the shared log queue and display them.

        Reschedules itself every 50 ms while the drainer is active,
        using Tk's after() to stay on the main thread.
        """
        try:
            while True: msg, kind = _log_queue.get_nowait(); self._log(msg, kind)
        except queue.Empty: pass
        if getattr(self, '_drainer_active', False):
            self.after(50, self._drain_log_queue)

    # ── Actions ────────────────────────────────────────────────────────────────

    def _browse_folder(self):
        """Open a native directory picker dialog and apply the selected folder."""
        folder = filedialog.askdirectory(title="Select folder to share")
        if folder: self._select_folder(folder)

    def _select_folder(self, folder: str):
        """
        Apply *folder* as the new root directory.

        Updates the display label, appends to the history list, and — if the
        server is already running — hot-swaps the root, rebuilds the index,
        restarts the watcher, and notifies WebSocket clients.
        """
        self._selected_folder.set(folder)
        name = Path(folder).name or folder
        self._folder_display.configure(text=name, fg=FG(), highlightbackground=FG())
        if folder not in self._folder_history: self._folder_history.append(folder)
        self._refresh_history()
        if self._running:
            global ROOT_DIR, _file_index, _ws_manager
            ROOT_DIR = Path(folder).resolve()
            _file_index.flush_if_dirty(ROOT_DIR); _file_index.clear(); _file_index.build(ROOT_DIR)
            _start_watcher(ROOT_DIR); _file_index.start_periodic_flush(ROOT_DIR)
            if _ws_manager: _ws_manager.notify_file_change('/')
            self._log(f"ROOT   changed → {ROOT_DIR}", "info")

    def _toggle_server(self):
        """Start the server if it is stopped, or stop it if it is running."""
        if self._running: self._stop_server()
        else: self._start_server()

    def _start_server(self):
        """
        Validate configuration, then start the HTTP and (optionally) WebSocket servers.

        - Validates the selected folder and port number.
        - Sets global server state (ROOT_DIR, SERVER_NAME, SERVER_PASSWORD).
        - Launches the ThreadingHTTPServer in a daemon thread with an 8 MB send buffer.
        - Launches the WebSocket server on port+1 in a separate daemon thread.
        - Triggers an async file index build and starts the directory watcher.
        - Updates the UI to reflect the ONLINE state.
        """
        global ROOT_DIR, SERVER_NAME, SERVER_PASSWORD, _ws_manager

        folder = self._selected_folder.get()
        if not folder:
            messagebox.showwarning("No folder", "Please select a folder to share first."); return

        root = Path(folder).resolve()
        if not root.exists() or not root.is_dir():
            messagebox.showerror("Invalid folder", f"Folder not found:\n{root}"); return

        try: port = int(self._port_var.get())
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be an integer."); return

        ROOT_DIR = root; SERVER_NAME = self._name_var.get() or socket.gethostname()
        SERVER_PASSWORD = self._password_var.get().strip()
        _file_index.clear()

        global _log_callback
        _log_callback = lambda msg, kind="info": None
        self._start_log_drainer()

        try:
            self._server = ThreadingHTTPServer(("0.0.0.0", port), NetShareHandler)
            self._server.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024
            )
        except OSError as e:
            messagebox.showerror("Port error", f"Cannot bind port {port}:\n{e}"); return

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start(); _file_index.build(ROOT_DIR); _start_watcher(ROOT_DIR)
        _file_index.start_periodic_flush(ROOT_DIR)

        ws_port = port + 1
        if HAS_WEBSOCKETS:
            _ws_manager = WebSocketManager()
            self._ws_thread = threading.Thread(target=_run_ws_server,
                                               args=("0.0.0.0", ws_port, _ws_manager), daemon=True)
            self._ws_thread.start()
        else:
            _ws_manager = None
            self._log("websockets not installed — persistent connection disabled", "dim")
            self._log("→  pip install websockets", "dim")

        self._running = True
        self._log(f"HTTP   :{port}   running", "ok")
        if HAS_WEBSOCKETS: self._log(f"WS     :{ws_port}   running", "ok")
        self._log(f"ROOT   {root}", "info")
        self._log("AUTH   password protection enabled" if SERVER_PASSWORD else "AUTH   no password (open access)",
                  "ok" if SERVER_PASSWORD else "dim")

        self._toggle_btn.configure(text="STOP SERVER", bg=DANGER())
        self._add_hover(self._toggle_btn, DANGER(), "#991111", text_normal=FG(), text_hover=FG())
        self._toggle_btn.configure(fg=FG())
        self._status_canvas.itemconfig(self._status_dot_id, fill="#22cc44")
        self._status_lbl.configure(text="ONLINE", fg=FG())
        self._update_addr_block(port, ws_port if HAS_WEBSOCKETS else None)
        self.after(100, lambda: self._canvas.yview_moveto(1.0))

    def _stop_server(self):
        """
        Gracefully shut down the HTTP and WebSocket servers.

        Notifies WebSocket clients, flushes the file index cache, stops the
        directory watcher, shuts down the HTTP server in a background thread,
        and resets the UI to the OFFLINE state.
        """
        global _log_callback, _ws_manager
        if _ws_manager: _ws_manager.notify_server_stopping(); _ws_manager = None
        _file_index.flush_if_dirty(ROOT_DIR); _file_index.clear(); _stop_watcher()
        if self._server:
            threading.Thread(target=self._server.shutdown, daemon=True).start()
            self._server = None
        self._ws_thread = None; self._running = False; _log_callback = None
        self._stop_log_drainer(); self._log("server stopped", "dim")
        self._toggle_btn.configure(text="START SERVER", bg=FG(), fg=BG())
        self._add_hover(self._toggle_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())
        self._status_canvas.itemconfig(self._status_dot_id, fill=FG3())
        self._status_lbl.configure(text="OFFLINE", fg=FG3())
        self._draw_offline_placeholder()

    def _update_addr_block(self, port: int, ws_port):
        """
        Rebuild the addresses section with one row per local network IP.

        Each row shows the HTTP URL, an optional WebSocket port badge,
        a COPY button, and (if qrcode is installed) a QR button.
        """
        for w in self._addr_frame.winfo_children(): w.destroy()
        ips = get_local_ips()
        for i, ip in enumerate(ips):
            url = f"http://{ip}:{port}"
            row = tk.Frame(self._addr_frame, bg=BG())
            row.pack(fill="x", pady=(0, self._s(6)))
            tk.Label(row, text=f"{i+1:02d}", font=(FONT_MONO, self._fs(8)),
                     fg=FG3(), bg=BG(), width=3, anchor="w").pack(side="left")
            url_lbl = tk.Label(row, text=url, font=(FONT_MONO, self._fs(10), "bold"),
                               fg=FG(), bg=BG(), cursor="hand2")
            url_lbl.pack(side="left")
            url_lbl.bind("<Button-1>", lambda e, u=url: self._copy(u))
            if ws_port:
                tk.Label(row, text=f"WS :{ws_port}", font=(FONT_MONO, self._fs(8)),
                         fg=FG3(), bg=BG()).pack(side="left", padx=(self._s(10), 0))
            if HAS_QRCODE:
                qr_btn = tk.Button(row, text="QR", font=(FONT_MONO, self._fs(8)),
                                   fg=FG3(), bg=BG(), activeforeground=FG(), activebackground=BG(),
                                   relief="flat", bd=0, cursor="hand2", padx=self._s(8),
                                   command=lambda u=url: self._show_qr(u))
                qr_btn.pack(side="right")
            copy_btn = tk.Button(row, text="COPY", font=(FONT_MONO, self._fs(8)),
                                 fg=FG3(), bg=BG(), activeforeground=FG(), activebackground=BG(),
                                 relief="flat", bd=0, cursor="hand2", padx=self._s(8),
                                 command=lambda u=url: self._copy(u))
            copy_btn.pack(side="right")
            if i < len(ips) - 1:
                tk.Frame(self._addr_frame, bg=BORDER(), height=1).pack(fill="x", pady=(0, self._s(6)))

    # ── QR ─────────────────────────────────────────────────────────────────────

    def _show_qr(self, url: str):
        """
        Generate and display a QR code for *url* in a Toplevel window.

        Uses high error-correction level (H) so that a centered logo overlay
        does not break scannability. The logo is the application favicon if
        present, otherwise a 'NS' monogram is drawn with Pillow.
        Theme-aware colours are applied to the QR matrix.
        """
        try:
            import qrcode as _qr
            from PIL import ImageTk, Image as _PilImg, ImageDraw
        except ImportError:
            messagebox.showinfo("QR Code", "Install Pillow:\npip install pillow qrcode")
            return

        QR_SIZE   = 260
        LOGO_FRAC = 0.22

        ico_path = Path(__file__).parent / "favicon.ico"

        qr = _qr.QRCode(
            error_correction=_qr.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)

        is_dark = _theme.get("BG", "#000") in ("#000000", "#0f0f0f", "#1a1a1a")
        qr_fg   = "#ffffff" if is_dark else "#0a0a0a"
        qr_bg   = "#000000" if is_dark else "#ffffff"

        img_pil = qr.make_image(fill_color=qr_fg, back_color=qr_bg).convert("RGBA")
        img_pil = img_pil.resize((QR_SIZE, QR_SIZE), _PilImg.LANCZOS)

        logo_px = int(QR_SIZE * LOGO_FRAC)
        logo_img = None

        if ico_path.exists():
            try:
                raw = _PilImg.open(ico_path).convert("RGBA")
                bg_img = _PilImg.new("RGBA", (logo_px, logo_px), (0, 0, 0, 0))
                draw_bg = ImageDraw.Draw(bg_img)
                draw_bg.rounded_rectangle(
                    [0, 0, logo_px - 1, logo_px - 1],
                    radius=logo_px // 5,
                    fill=qr_bg + "ff" if len(qr_bg) == 7 else qr_bg,
                )
                inner = int(logo_px * 0.72)
                raw = raw.resize((inner, inner), _PilImg.LANCZOS)
                offset = (logo_px - inner) // 2
                bg_img.paste(raw, (offset, offset), mask=raw)
                logo_img = bg_img
            except Exception:
                logo_img = None

        if logo_img is None:
            from PIL import ImageFont
            logo_img = _PilImg.new("RGBA", (logo_px, logo_px), (0, 0, 0, 0))
            draw = ImageDraw.Draw(logo_img)
            draw.rounded_rectangle(
                [0, 0, logo_px - 1, logo_px - 1],
                radius=logo_px // 5,
                fill=qr_fg,
            )
            font_size = max(10, logo_px // 2)
            fnt = None
            for fp in ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
                       "/System/Library/Fonts/Courier.ttc",
                       "C:/Windows/Fonts/cour.ttf"]:
                try: fnt = ImageFont.truetype(fp, font_size); break
                except Exception: pass
            if fnt is None:
                fnt = ImageFont.load_default()
            bbox = draw.textbbox((0, 0), "NS", font=fnt)
            draw.text(
                ((logo_px - (bbox[2]-bbox[0])) // 2 - bbox[0],
                 (logo_px - (bbox[3]-bbox[1])) // 2 - bbox[1]),
                "NS", font=fnt, fill=qr_bg,
            )

        pos = ((QR_SIZE - logo_px) // 2, (QR_SIZE - logo_px) // 2)
        img_pil.paste(logo_img, pos, mask=logo_img)

        img_tk = ImageTk.PhotoImage(img_pil)

        win = tk.Toplevel(self)
        win.title("QR — NetShare Player")
        win.configure(bg=BG())
        win.resizable(False, False)

        if ico_path.exists():
            try:
                win.iconbitmap(str(ico_path))
            except Exception:
                pass

        frame = tk.Frame(win, bg=FG(), padx=self._s(16), pady=self._s(16))
        frame.pack(padx=self._s(24), pady=(self._s(24), self._s(12)))
        tk.Label(frame, image=img_tk, bg=FG()).pack()
        win._img_ref = img_tk

        tk.Label(win, text=url, font=(FONT_MONO, self._fs(9)),
                 fg=FG3(), bg=BG()).pack(pady=(0, self._s(16)))

    # ── Log ────────────────────────────────────────────────────────────────────

    def _log(self, msg: str, kind: str = "info"):
        """Append a timestamped message to the log Text widget with appropriate colour tagging."""
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_text.configure(state="normal")
        self._log_text.insert("end", f"[{ts}]  ", "ts")
        self._log_text.insert("end", f"{msg}\n", kind)
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def _copy(self, text: str):
        """Copy *text* to the system clipboard and log a confirmation."""
        self.clipboard_clear(); self.clipboard_append(text)
        self._log(f"copied  {text}", "dim")

    def _add_hover(self, widget, normal_bg, hover_bg, text_normal=None, text_hover=None):
        """
        Attach mouse-enter / mouse-leave bindings to a widget for hover colour feedback.

        Args:
            normal_bg: Background colour when the mouse is not over the widget.
            hover_bg:  Background colour when the mouse is over the widget.
            text_normal: Foreground colour in normal state (optional).
            text_hover:  Foreground colour in hover state (optional).
        """
        def on_enter(e):
            widget.configure(bg=hover_bg)
            if text_hover: widget.configure(fg=text_hover)
        def on_leave(e):
            widget.configure(bg=normal_bg)
            if text_normal: widget.configure(fg=text_normal)
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def _on_close(self):
        """Stop the server (if running) and destroy the main window."""
        if self._running: self._stop_server()
        self.destroy()


if __name__ == "__main__":
    _ensure_single_instance()

    if not HAS_WEBSOCKETS:
        print("⚠  Module 'websockets' not found.")
        print("   Install it: pip install websockets")
        print("   Server will start in HTTP-only mode.\n")
    if not HAS_WATCHDOG:
        print("⚠  Module 'watchdog' not found.")
        print("   Install it: pip install watchdog")
        print("   Live directory updates will be disabled.\n")
    app = App()
    app.mainloop()