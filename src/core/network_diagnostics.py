"""Bounded primitives for private LAN connection diagnostics."""

from __future__ import annotations

import hashlib
import time


MAX_THROUGHPUT_BYTES = 2 * 1024 * 1024
DEFAULT_THROUGHPUT_BYTES = 512 * 1024
_BLOCK = hashlib.sha256(b"netshare-private-diagnostic").digest() * 1024


def diagnostic_ping() -> dict:
    return {"ok": True, "server_time_ms": int(time.time() * 1000), "scope": "lan"}


def bounded_throughput_size(requested: object) -> int:
    try:
        size = int(requested)
    except (TypeError, ValueError):
        size = DEFAULT_THROUGHPUT_BYTES
    return max(1024, min(size, MAX_THROUGHPUT_BYTES))


def throughput_chunks(size: int):
    remaining = bounded_throughput_size(size)
    while remaining:
        chunk = _BLOCK[: min(len(_BLOCK), remaining)]
        remaining -= len(chunk)
        yield chunk
