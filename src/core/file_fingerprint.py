"""Reusable streaming file fingerprints for future cross-root deduplication."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


DEFAULT_HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class FileFingerprint:
    algorithm: str
    digest: str
    size: int
    modified_ns: int


def fingerprint_file(
    path: Path, *, chunk_bytes: int = DEFAULT_HASH_CHUNK_BYTES,
) -> FileFingerprint:
    """Return a SHA-256 fingerprint without loading the whole file in memory.

    Raises ``OSError`` if the file cannot be read and ``RuntimeError`` if it
    changes while being hashed, so callers never cache an unstable digest.
    """
    target = Path(path)
    chunk_bytes = int(chunk_bytes)
    if chunk_bytes <= 0:
        raise ValueError("hash chunk size must be positive")
    before = target.stat()
    if not target.is_file():
        raise IsADirectoryError(str(target))
    digest = hashlib.sha256()
    with target.open("rb") as stream:
        while chunk := stream.read(chunk_bytes):
            digest.update(chunk)
    after = target.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError("file changed while hashing")
    return FileFingerprint("sha256", digest.hexdigest(), after.st_size, after.st_mtime_ns)
