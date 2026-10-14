"""Correlation IDs shared by application-service operations."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import uuid

_CORRELATION_ID: ContextVar[str | None] = ContextVar(
    "netshare_application_correlation_id", default=None
)


def new_correlation_id() -> str:
    """Return a compact opaque ID suitable for logs and bug reports."""
    return uuid.uuid4().hex


def current_correlation_id() -> str | None:
    return _CORRELATION_ID.get()


def normalize_correlation_id(value: object | None) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return new_correlation_id()
    # Bound hostile/untrusted IDs before they reach logs.
    return candidate[:128]


@contextmanager
def correlation_scope(correlation_id: object | None = None):
    """Bind a correlation ID for the duration of one logical operation."""
    cid = normalize_correlation_id(correlation_id or current_correlation_id())
    token = _CORRELATION_ID.set(cid)
    try:
        yield cid
    finally:
        _CORRELATION_ID.reset(token)
