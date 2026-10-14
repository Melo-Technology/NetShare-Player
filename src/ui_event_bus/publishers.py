"""Publisher façade for future backend producers.

No current Tkinter/runtime producer is attached in Step 03.  This wrapper exists so future
integration points depend on the public bus contract rather than its queue internals.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from src.application.correlation import current_correlation_id

from .event_bus import UiEventBus


class EventPublisher:
    def __init__(self, bus: UiEventBus) -> None:
        self._bus = bus

    def publish(
        self,
        event_name: str,
        payload: Mapping[str, Any] | None = None,
        *,
        correlation_id: str | None = None,
    ) -> bool:
        return self._bus.publish(
            event_name,
            dict(payload or {}),
            correlation_id=correlation_id or current_correlation_id(),
        )
