"""Failure-contained structured logging for the PyWebView shell.

The shell deliberately logs to Python logging only.  It never publishes shell
observability into the legacy Tkinter queues, preserving the single-consumer
queue guarantees established in Step 03.
"""

from __future__ import annotations

from typing import Any

from src.application.observability import CompositeLogSink, PythonLoggingSink, StructuredLogger


def build_shell_logger(component: str = "DesktopShell") -> StructuredLogger:
    return StructuredLogger(
        component,
        sink=CompositeLogSink((PythonLoggingSink("netshare.desktop_shell"),)),
    )


def safe_log(
    logger: StructuredLogger | Any,
    event: str,
    *,
    operation: str,
    status: str,
    correlation_id: str | None = None,
    level: str = "info",
    **fields: Any,
) -> None:
    """Best-effort logging: diagnostics must never crash the shell."""
    try:
        logger.emit(
            event,
            operation=operation,
            status=status,
            correlation_id=correlation_id,
            level=level,
            **fields,
        )
    except Exception:
        return
