"""Bounded on-disk LRU cache for generated image and video thumbnails."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path

from src.core.data_vault import secure_unlink
from src.core.vault_storage import read_bytes, write_bytes


class ThumbnailCache:
    """Keep thumbnail bytes bounded while favoring recently reused entries."""

    def __init__(
        self,
        root: Path,
        *,
        max_bytes: int = 256 * 1024 * 1024,
        max_entries: int = 2_000,
        max_entry_bytes: int = 512 * 1024,
        max_unused_days: int = 60,
    ) -> None:
        self.root = Path(root)
        self.max_bytes = max(0, int(max_bytes))
        self.max_entries = max(0, int(max_entries))
        self.max_entry_bytes = max(0, int(max_entry_bytes))
        self.max_unused_days = max(1, int(max_unused_days))
        self._lock = threading.RLock()
        # Filesystem mtimes are not a sufficiently precise LRU clock on every
        # supported platform/filesystem.  Keep a process-local monotonic rank
        # for exact ordering while retaining mtime as the restart fallback.
        self._recency_counter = 0
        self._recency: dict[str, int] = {}

    def _mark_recent(self, path: Path) -> None:
        self._recency_counter += 1
        self._recency[path.name] = self._recency_counter

    @staticmethod
    def key(path: Path, width: int, height: int) -> str:
        stat = path.stat()
        identity = (
            f"{path.resolve()}\0{stat.st_size}\0{stat.st_mtime_ns}"
            f"\0{int(width)}\0{int(height)}"
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def get(self, key: str) -> bytes | None:
        cache_path = self.root / f"{key}.jpg"
        with self._lock:
            try:
                data = read_bytes(cache_path, purpose=f"thumbnail:{key}")
                if not data or len(data) > self.max_entry_bytes:
                    secure_unlink(cache_path)
                    return None
                # mtime is the LRU clock; touching only on hits keeps cleanup cheap.
                os.utime(cache_path, None)
                self._mark_recent(cache_path)
                return data
            except (FileNotFoundError, OSError):
                return None

    def put(self, key: str, data: bytes) -> bool:
        if (
            not data
            or len(data) > self.max_entry_bytes
            or self.max_bytes <= 0
            or self.max_entries <= 0
        ):
            return False
        with self._lock:
            try:
                self.root.mkdir(parents=True, exist_ok=True)
                target = self.root / f"{key}.jpg"
                write_bytes(target, data, purpose=f"thumbnail:{key}")
                self._mark_recent(target)
                self.clean()
                return True
            except OSError:
                return False

    def clear(self) -> dict[str, int]:
        """Remove every generated thumbnail under this cache root."""
        removed_files = 0
        removed_bytes = 0
        with self._lock:
            try:
                entries = list(self.root.iterdir()) if self.root.exists() else []
            except OSError:
                entries = []
            for path in entries:
                if not path.is_file():
                    continue
                try:
                    size = int(path.stat().st_size)
                    secure_unlink(path)
                    self._recency.pop(path.name, None)
                    removed_files += 1
                    removed_bytes += size
                except OSError:
                    continue
            try:
                self.root.rmdir()
            except OSError:
                pass
        return {"files": removed_files, "bytes": removed_bytes}

    def clean(self) -> None:
        """Evict least-recently-used files until both hard limits are met."""
        with self._lock:
            try:
                files = []
                for path in self.root.glob("*.jpg"):
                    try:
                        stat = path.stat()
                        rank = self._recency.get(path.name)
                        # Entries observed in this process use the exact
                        # monotonic order.  Older on-disk entries (no rank yet)
                        # remain ordered by mtime and are naturally evicted
                        # before entries actively reused after startup.
                        order = (1, rank) if rank is not None else (0, stat.st_mtime_ns)
                        files.append((order, stat.st_size, path))
                    except OSError:
                        continue
            except OSError:
                return

            # First purge entries that have not been consulted within the
            # retention window. mtime is deliberately touched on every hit.
            cutoff = time.time() - (self.max_unused_days * 24 * 60 * 60)
            retained = []
            for order, size, path in files:
                try:
                    if path.stat().st_mtime < cutoff:
                        secure_unlink(path)
                        self._recency.pop(path.name, None)
                        continue
                except OSError:
                    continue
                retained.append((order, size, path))

            files = retained
            files.sort(key=lambda item: item[0])
            total = sum(item[1] for item in files)
            while files and (len(files) > self.max_entries or total > self.max_bytes):
                _, size, path = files.pop(0)
                try:
                    secure_unlink(path)
                    self._recency.pop(path.name, None)
                    total -= size
                except OSError:
                    continue


_default_cache: ThumbnailCache | None = None
_default_lock = threading.Lock()


def get_thumbnail_cache() -> ThumbnailCache:
    global _default_cache
    with _default_lock:
        if _default_cache is None:
            import src.state as state

            try:
                max_unused_days = max(1, int(os.environ.get("NETSHARE_CACHE_MAX_UNUSED_DAYS", "60")))
            except (TypeError, ValueError):
                max_unused_days = 60
            _default_cache = ThumbnailCache(
                state._CONFIG_DIR / "thumbnail_cache",
                max_unused_days=max_unused_days,
            )
            _default_cache.clean()
        return _default_cache
