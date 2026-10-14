"""UiEventBus-specific exceptions.

These exceptions describe caller/programmer errors at the event-bus boundary.  Runtime
subscriber failures are intentionally contained by :class:`UiEventBus` and never escape
through these types.
"""

from __future__ import annotations


class UiEventBusError(Exception):
    """Base exception for event-bus contract errors."""


class UnknownEventError(UiEventBusError):
    """Raised when a publisher uses an event name that is not registered."""


class EventPayloadValidationError(UiEventBusError):
    """Raised when an event payload violates its declared contract."""


class SubscriptionError(UiEventBusError):
    """Raised for invalid subscription operations."""
