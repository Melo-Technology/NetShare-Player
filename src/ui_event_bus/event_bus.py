"""Backend-only, bounded, asynchronous UI event bus.

Backpressure strategy
---------------------
The internal queue has a configurable finite capacity.  ``publish`` never blocks a
backend producer waiting for a slow/failing future UI consumer.  If the queue is full,
the newest event is rejected (``drop_newest``), ``event.queue_full`` and
``event.dropped`` are logged, and ``publish`` returns ``False``.

This queue is owned exclusively by UiEventBus.  The implementation intentionally has no
adapter for any pre-existing application/GUI queue.  Live sources that cannot safely fan
out must remain deferred until a non-destructive producer exists.
"""

from __future__ import annotations

from datetime import datetime, timezone
import itertools
from queue import Empty, Full, Queue
from threading import Event as ThreadEvent, Lock, Thread
import time
from typing import Any

from src.application.correlation import (
    correlation_scope,
    current_correlation_id,
    normalize_correlation_id,
)

from .events import EventName, UiEvent, as_event_name, validate_event_payload
from .exceptions import EventPayloadValidationError, UnknownEventError
from .observability import EventBusObserver
from .subscriptions import Subscriber, SubscriptionRegistry


class UiEventBus:
    """Bounded event dispatcher with per-subscriber failure isolation."""

    BACKPRESSURE_POLICY = "drop_newest"

    def __init__(
        self,
        *,
        max_queue_size: int = 512,
        logger: Any | None = None,
        auto_start: bool = True,
        worker_name: str = "NetShare-UiEventBus",
    ) -> None:
        try:
            capacity = int(max_queue_size)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_queue_size must be a positive integer") from exc
        if capacity <= 0:
            raise ValueError("max_queue_size must be a positive integer")

        self._queue: Queue[UiEvent] = Queue(maxsize=capacity)
        self._subscriptions = SubscriptionRegistry()
        self._observer = EventBusObserver(logger)
        self._sequence = itertools.count(1)
        self._sequence_lock = Lock()
        self._lifecycle_lock = Lock()
        self._stop = ThreadEvent()
        self._accepting = True
        self._worker: Thread | None = None
        self._worker_name = str(worker_name or "NetShare-UiEventBus")
        if auto_start:
            self.start()

    @property
    def max_queue_size(self) -> int:
        return self._queue.maxsize

    @property
    def backpressure_policy(self) -> str:
        return self.BACKPRESSURE_POLICY

    def start(self) -> bool:
        """Start the single dispatcher worker; safe to call more than once."""
        with self._lifecycle_lock:
            if self._worker is not None and self._worker.is_alive():
                return False
            self._stop.clear()
            self._accepting = True
            worker = Thread(target=self._dispatch_loop, name=self._worker_name, daemon=True)
            self._worker = worker
            worker.start()
            return True

    def close(self, *, timeout: float = 2.0, drain: bool = True) -> bool:
        """Stop accepting events and terminate the worker.

        ``drain=True`` gives already accepted events a chance to be delivered before the
        worker exits.  It never redirects or drains any external queue.
        """
        with self._lifecycle_lock:
            self._accepting = False
            self._stop.set()
            worker = self._worker
        if worker is None:
            return True
        if drain:
            self.wait_until_idle(timeout=max(0.0, float(timeout)))
        worker.join(timeout=max(0.0, float(timeout)))
        return not worker.is_alive()

    def subscribe(self, event_name: str, callback: Subscriber) -> str:
        return self._subscriptions.subscribe(event_name, callback)

    def unsubscribe(self, token: str) -> bool:
        return self._subscriptions.unsubscribe(token)

    def publish(
        self,
        event_name: str,
        payload: dict[str, Any] | None = None,
        *,
        correlation_id: str | None = None,
    ) -> bool:
        """Validate and enqueue an event without blocking the producer.

        Contract errors raise typed event-bus exceptions.  Queue saturation and a closed
        bus are operational conditions and return ``False`` after structured logging.
        """
        started = time.perf_counter()
        cid = normalize_correlation_id(correlation_id or current_correlation_id())
        try:
            typed_name: EventName = as_event_name(str(event_name))
            validated = validate_event_payload(typed_name, payload)
        except (UnknownEventError, EventPayloadValidationError):
            duration = (time.perf_counter() - started) * 1000.0
            self._observer.emit(
                "event.dropped",
                event_name=str(event_name),
                status="validation_failed",
                correlation_id=cid,
                duration_ms=duration,
                operation="publish",
                reason="validation_failed",
            )
            raise

        if not self._accepting:
            duration = (time.perf_counter() - started) * 1000.0
            self._observer.emit(
                "event.dropped",
                event_name=typed_name,
                status="closed",
                correlation_id=cid,
                duration_ms=duration,
                operation="publish",
                reason="bus_closed",
            )
            return False

        with self._sequence_lock:
            sequence = next(self._sequence)
        event: UiEvent = {
            "name": typed_name,
            "payload": validated,
            "correlation_id": cid,
            "published_at": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "sequence": sequence,
        }
        try:
            self._queue.put_nowait(event)
        except Full:
            duration = (time.perf_counter() - started) * 1000.0
            self._observer.emit(
                "event.queue_full",
                event_name=typed_name,
                status="full",
                correlation_id=cid,
                duration_ms=duration,
                operation="publish",
                queue_size=self._queue.qsize(),
                queue_capacity=self._queue.maxsize,
                backpressure_policy=self.BACKPRESSURE_POLICY,
            )
            self._observer.emit(
                "event.dropped",
                event_name=typed_name,
                status="dropped",
                correlation_id=cid,
                duration_ms=duration,
                operation="publish",
                reason="queue_full",
                backpressure_policy=self.BACKPRESSURE_POLICY,
            )
            return False

        duration = (time.perf_counter() - started) * 1000.0
        self._observer.emit(
            "event.published",
            event_name=typed_name,
            status="success",
            correlation_id=cid,
            duration_ms=duration,
            operation="publish",
            sequence=sequence,
            queue_size=self._queue.qsize(),
        )
        return True

    def wait_until_idle(self, *, timeout: float = 2.0) -> bool:
        """Wait until all events accepted so far have been processed."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() <= deadline:
            if self._queue.unfinished_tasks == 0:
                return True
            time.sleep(0.002)
        return self._queue.unfinished_tasks == 0

    def _dispatch_loop(self) -> None:
        while True:
            if self._stop.is_set() and self._queue.empty():
                return
            try:
                event = self._queue.get(timeout=0.05)
            except Empty:
                continue
            try:
                self._deliver(event)
            finally:
                self._queue.task_done()

    def _deliver(self, event: UiEvent) -> None:
        subscriptions = self._subscriptions.snapshot(event["name"])
        for subscription in subscriptions:
            started = time.perf_counter()
            try:
                # Correlation context is restored in the dispatcher thread so subscriber
                # code can use current_correlation_id() without receiving a side channel.
                with correlation_scope(event["correlation_id"]):
                    subscription.callback(event)
            except Exception as exc:
                duration = (time.perf_counter() - started) * 1000.0
                self._observer.emit(
                    "event.delivery_failed",
                    event_name=event["name"],
                    status="failed",
                    correlation_id=event["correlation_id"],
                    duration_ms=duration,
                    operation="deliver",
                    sequence=event["sequence"],
                    subscriber_id=subscription.token,
                    error_type=type(exc).__name__,
                )
                continue

            duration = (time.perf_counter() - started) * 1000.0
            self._observer.emit(
                "event.delivered",
                event_name=event["name"],
                status="success",
                correlation_id=event["correlation_id"],
                duration_ms=duration,
                operation="deliver",
                sequence=event["sequence"],
                subscriber_id=subscription.token,
            )

    def __enter__(self) -> "UiEventBus":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()
