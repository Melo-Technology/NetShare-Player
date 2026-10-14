"""Backend-only UiEventBus infrastructure."""

from .event_bus import UiEventBus
from .events import (
    ACTIVITY_APPENDED,
    DEVICES_CHANGED,
    EVENT_NAMES,
    METRICS_UPDATED,
    SERVER_ADDRESSES_CHANGED,
    SERVER_STATUS_CHANGED,
    SETTINGS_CHANGED,
    SHARING_CHANGED,
    TOAST_REQUESTED,
    UiEvent,
)
from .exceptions import (
    EventPayloadValidationError,
    SubscriptionError,
    UiEventBusError,
    UnknownEventError,
)
from .publishers import EventPublisher

__all__ = [
    "UiEventBus",
    "EventPublisher",
    "UiEvent",
    "UiEventBusError",
    "UnknownEventError",
    "EventPayloadValidationError",
    "SubscriptionError",
    "EVENT_NAMES",
    "SERVER_STATUS_CHANGED",
    "SERVER_ADDRESSES_CHANGED",
    "DEVICES_CHANGED",
    "SHARING_CHANGED",
    "SETTINGS_CHANGED",
    "METRICS_UPDATED",
    "ACTIVITY_APPENDED",
    "TOAST_REQUESTED",
]
