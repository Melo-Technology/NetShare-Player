"""Failure-contained structured logging for the UiEventBus.

The default sink deliberately uses Python logging only.  It does not bridge into the
legacy GUI log pipeline, which keeps this package independent from legacy consumer queues.
"""

from __future__ import annotations

from typing import Any

from src.application.observability import CompositeLogSink, PythonLoggingSink, StructuredLogger


def build_event_bus_logger() -> StructuredLogger:
    return StructuredLogger(
        "UiEventBus",
        sink=CompositeLogSink((PythonLoggingSink("netshare.ui_event_bus"),)),
    )


class EventBusObserver:
    """Small safety wrapper: observability must never break event delivery."""

    def __init__(self, logger: StructuredLogger | Any | None = None) -> None:
        self._logger = logger or build_event_bus_logger()

    def emit(
        self,
        log_event: str,
        *,
        event_name: str,
        status: str,
        correlation_id: str,
        duration_ms: float,
        operation: str,
        **fields: Any,
    ) -> None:
        try:
            self._logger.emit(
                log_event,
                operation=operation,
                status=status,
                correlation_id=correlation_id,
                duration_ms=round(max(0.0, float(duration_ms)), 3),
                event_name=event_name,
                **fields,
            )
        except Exception:
            # Crash containment wins over diagnostics, including injected test loggers.
            return
