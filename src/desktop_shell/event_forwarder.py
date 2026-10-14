"""Non-blocking UiEventBus → WebView event forwarding adapter.

This adapter owns a new bounded queue.  It never reads a legacy Tkinter queue and
never adds a second consumer to any pre-existing single-consumer source.
"""

from __future__ import annotations

import json
from queue import Empty, Full, Queue
from threading import Event as ThreadEvent, Lock, Thread
import time
from typing import Any

from src.ui_event_bus import EVENT_NAMES, UiEvent, UiEventBus

from .observability import build_shell_logger, safe_log


class WebViewEventForwarder:
    BACKPRESSURE_POLICY = "drop_newest"

    def __init__(
        self,
        bus: UiEventBus,
        *,
        max_queue_size: int = 256,
        logger: Any | None = None,
    ) -> None:
        capacity = int(max_queue_size)
        if capacity <= 0:
            raise ValueError("max_queue_size must be a positive integer")
        self._bus = bus
        self._queue: Queue[UiEvent] = Queue(maxsize=capacity)
        self._log = logger or build_shell_logger("WebViewEventForwarder")
        self._window: Any | None = None
        self._window_lock = Lock()
        self._ready = ThreadEvent()
        self._stop = ThreadEvent()
        self._worker: Thread | None = None
        self._tokens: list[str] = []

    @property
    def max_queue_size(self) -> int:
        return self._queue.maxsize

    def attach_window(self, window: Any) -> None:
        with self._window_lock:
            self._window = window

    def mark_ready(self) -> None:
        self._ready.set()

    def start(self) -> bool:
        if self._worker is not None and self._worker.is_alive():
            return False
        if not self._tokens:
            for event_name in sorted(EVENT_NAMES):
                self._tokens.append(self._bus.subscribe(event_name, self._enqueue))
        self._stop.clear()
        worker = Thread(target=self._run, name="NetShare-WebViewEventForwarder", daemon=True)
        self._worker = worker
        worker.start()
        return True

    def close(self, *, timeout: float = 1.0) -> bool:
        self._stop.set()
        self._ready.set()
        for token in tuple(self._tokens):
            try:
                self._bus.unsubscribe(token)
            except Exception:
                pass
        self._tokens.clear()
        worker = self._worker
        if worker is None:
            return True
        worker.join(timeout=max(0.0, float(timeout)))
        return not worker.is_alive()

    def wait_until_idle(self, *, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() <= deadline:
            if self._queue.unfinished_tasks == 0:
                return True
            time.sleep(0.002)
        return self._queue.unfinished_tasks == 0

    def _enqueue(self, event: UiEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except Full:
            safe_log(
                self._log,
                "shell.event.queue_full",
                operation="enqueue",
                status="full",
                correlation_id=event.get("correlation_id"),
                queue_size=self._queue.qsize(),
                queue_capacity=self._queue.maxsize,
                backpressure_policy=self.BACKPRESSURE_POLICY,
                event_name=event.get("name", ""),
            )
            safe_log(
                self._log,
                "shell.event.dropped",
                operation="enqueue",
                status="dropped",
                correlation_id=event.get("correlation_id"),
                event_name=event.get("name", ""),
                reason="queue_full",
            )

    def _run(self) -> None:
        while True:
            if self._stop.is_set() and self._queue.empty():
                return
            try:
                event = self._queue.get(timeout=0.05)
            except Empty:
                continue
            try:
                if not self._wait_until_ready():
                    self._log_drop(event, "shell_closed_before_ready")
                    continue
                self._forward(event)
            finally:
                self._queue.task_done()

    def _wait_until_ready(self) -> bool:
        while not self._ready.wait(timeout=0.05):
            if self._stop.is_set():
                return False
        return not self._stop.is_set()

    def _forward(self, event: UiEvent) -> None:
        started = time.perf_counter()
        with self._window_lock:
            window = self._window
        if window is None:
            self._log_drop(event, "window_unavailable")
            return

        # ensure_ascii avoids raw U+2028/U+2029 separators in JS source.  UiEventBus
        # already guarantees JSON-native payloads, so no custom encoder is needed.
        payload = json.dumps(event, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        script = (
            "window.NetShareShell && "
            f"window.NetShareShell.receiveBackendEvent({payload});"
        )
        try:
            run_js = getattr(window, "run_js", None)
            if callable(run_js):
                run_js(script)
            else:
                window.evaluate_js(script)
        except Exception as exc:
            safe_log(
                self._log,
                "shell.event.forward_failed",
                operation="forward",
                status="failed",
                level="error",
                correlation_id=event.get("correlation_id"),
                duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                event_name=event.get("name", ""),
                error_type=type(exc).__name__,
            )
            return

        safe_log(
            self._log,
            "shell.event.forwarded",
            operation="forward",
            status="success",
            correlation_id=event.get("correlation_id"),
            duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
            event_name=event.get("name", ""),
            sequence=event.get("sequence"),
        )

    def _log_drop(self, event: UiEvent, reason: str) -> None:
        safe_log(
            self._log,
            "shell.event.dropped",
            operation="forward",
            status="dropped",
            correlation_id=event.get("correlation_id"),
            event_name=event.get("name", ""),
            reason=reason,
        )
