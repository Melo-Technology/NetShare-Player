"""Read-only adapter over the existing global file index."""

from __future__ import annotations


class FileIndexAdapter:
    def __init__(self, file_index=None):
        if file_index is None:
            from src.core.file_index import _file_index
            file_index = _file_index
        self.file_index = file_index

    def total_files(self) -> int:
        return max(0, int(getattr(self.file_index, "total", 0)))

    def ready(self) -> bool:
        return bool(getattr(self.file_index, "ready", False))

    def paused(self) -> bool:
        paused = getattr(self.file_index, "paused", None)
        return bool(paused()) if callable(paused) else False
