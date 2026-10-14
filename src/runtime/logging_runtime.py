"""Bridge important Python logging records into the bounded Activity runtime.

The packaged desktop application runs without a console.  Warnings/errors from
backend modules that use :mod:`logging` would otherwise be invisible to the
user and absent from exported diagnostics.  This handler mirrors only warning
and error records into the existing non-destructive ActivityRuntime fan-out;
routine INFO observability stays in Python logging and does not flood the UI
buffer.
"""
from __future__ import annotations

import logging
import threading
import traceback

from src.runtime.activity_runtime import activity_runtime

_MAX_EXCEPTION_CHARS = 12_000
_INSTALLED = False
_INSTALL_LOCK = threading.Lock()


class ActivityLoggingHandler(logging.Handler):
    """Failure-contained logging.Handler that writes to ActivityRuntime."""

    _SKIP_PREFIXES = (
        "netshare.application",
        "netshare.desktop_shell",
    )

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if any(str(record.name).startswith(prefix) for prefix in self._SKIP_PREFIXES):
                return
            message = record.getMessage()
            if record.exc_info:
                rendered = "".join(traceback.format_exception(*record.exc_info)).strip()
                if rendered:
                    message = f"{message}\n{rendered[:_MAX_EXCEPTION_CHARS]}"
            kind = "error" if record.levelno >= logging.ERROR else "warning"
            activity_runtime.publish_log(
                f"PYLOG {record.name} {record.levelname} {message}",
                kind,
            )
        except Exception:
            # Diagnostics must never break the producer that emitted the log.
            return


def install_activity_logging_bridge() -> bool:
    """Install the bridge exactly once and return whether this call installed it."""
    global _INSTALLED
    with _INSTALL_LOCK:
        if _INSTALLED:
            return False
        root = logging.getLogger()
        for handler in root.handlers:
            if isinstance(handler, ActivityLoggingHandler):
                _INSTALLED = True
                return False
        root.addHandler(ActivityLoggingHandler())
        _INSTALLED = True
        return True


__all__ = ["ActivityLoggingHandler", "install_activity_logging_bridge"]
