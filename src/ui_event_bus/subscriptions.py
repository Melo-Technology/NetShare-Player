"""Thread-safe subscription registry for :mod:`src.ui_event_bus`."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
import uuid

from .events import EVENT_NAMES, EventName, UiEvent, as_event_name
from .exceptions import SubscriptionError

Subscriber = Callable[[UiEvent], None]


@dataclass(frozen=True, slots=True)
class Subscription:
    token: str
    event_name: EventName
    callback: Subscriber


class SubscriptionRegistry:
    """Maintain subscribers in registration order.

    Snapshotting before delivery allows subscribe/unsubscribe calls from callbacks without
    mutating the collection currently being iterated.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._by_event: dict[str, dict[str, Subscription]] = {
            event_name: {} for event_name in EVENT_NAMES
        }
        self._by_token: dict[str, Subscription] = {}

    def subscribe(self, event_name: str, callback: Subscriber) -> str:
        if not callable(callback):
            raise SubscriptionError("subscriber must be callable")
        typed_name = as_event_name(event_name)
        token = uuid.uuid4().hex
        subscription = Subscription(token, typed_name, callback)
        with self._lock:
            self._by_event[event_name][token] = subscription
            self._by_token[token] = subscription
        return token

    def unsubscribe(self, token: str) -> bool:
        normalized = str(token or "").strip()
        if not normalized:
            return False
        with self._lock:
            subscription = self._by_token.pop(normalized, None)
            if subscription is None:
                return False
            self._by_event[subscription.event_name].pop(normalized, None)
            return True

    def snapshot(self, event_name: str) -> tuple[Subscription, ...]:
        as_event_name(event_name)
        with self._lock:
            return tuple(self._by_event[event_name].values())

    def clear(self) -> None:
        with self._lock:
            for values in self._by_event.values():
                values.clear()
            self._by_token.clear()
