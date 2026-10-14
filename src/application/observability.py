"""Structured, failure-contained observability for the application layer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from typing import Any, Iterable, Mapping, Protocol

from .correlation import current_correlation_id
from src.secret_redaction import redact_secret_text


_ACTIVITY_IMPORTANT_EVENTS = frozenset({
    "settings.updated",
    "settings.validation_failed",
    "desktop_api.error",
    "service.failed",
    "event.delivery_failed",
    "event.queue_full",
    "event.dropped",
    "migration.fallback_used",
})

_SENSITIVE_KEYS = {
    "password", "local_password", "admin_password", "community_password",
    "web_password", "credential", "credential_hash", "token", "access_token",
    "refresh_token", "totp", "totp_secret", "private_key", "secret", "code",
    # C5.1 Data Vault material. These names are explicit instead of treating
    # every generic "key" field as secret (message_key/public_key are valid
    # observability fields).
    "recovery_key", "recovery_phrase", "dek", "kek", "vault_key",
    "wrapped_dek", "remembered_key", "data_vault_key",
}


def _redact(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if lowered in _SENSITIVE_KEYS or any(part in lowered for part in ("password", "token", "secret", "credential", "private_key")):
        return "<redacted>"
    if isinstance(value, Mapping):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return redact_secret_text(value)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)


class StructuredLogSink(Protocol):
    def emit(self, payload: Mapping[str, Any]) -> None: ...


@dataclass(slots=True)
class PythonLoggingSink:
    logger_name: str = "netshare.application"

    def emit(self, payload: Mapping[str, Any]) -> None:
        logger = logging.getLogger(self.logger_name)
        level_name = str(payload.get("level") or "info").upper()
        level = getattr(logging, level_name, logging.INFO)
        logger.log(level, json.dumps(dict(payload), ensure_ascii=False, sort_keys=True))


class StateLogSink:
    """Bridge only high-signal structured events to the bounded UI log stream.

    Full structured observability still goes to :class:`PythonLoggingSink`.  The
    Activity buffer is intentionally protected from routine DesktopApi/service
    success telemetry so real HTTP/API/video diagnostics cannot be evicted by
    the desktop shell's periodic refresh calls.
    """

    def emit(self, payload: Mapping[str, Any]) -> None:
        import src.state as state

        level = str(payload.get("level") or "info").lower()
        status = str(payload.get("status") or "").lower()
        event = str(payload.get("event") or "")
        important = (
            level in {"warning", "warn", "error", "critical"}
            or status in {"warning", "warn", "error", "failed", "failure"}
            or event in _ACTIVITY_IMPORTANT_EVENTS
            or event.endswith(".failed")
            or event.endswith(".error")
            or event.endswith(".dropped")
        )
        if not important:
            return
        if level in {"error", "critical"} or status in {"error", "failed", "failure"}:
            kind = "error"
        elif level in {"warning", "warn"} or status in {"warning", "warn"}:
            kind = "warning"
        elif status in {"success", "ok"}:
            kind = "ok"
        else:
            kind = "info"
        state._emit(
            "APP " + json.dumps(dict(payload), ensure_ascii=False, sort_keys=True),
            kind,
        )


class CompositeLogSink:
    """A broken observability sink must never break the server or service call."""

    def __init__(self, sinks: Iterable[StructuredLogSink]):
        self._sinks = tuple(sinks)

    def emit(self, payload: Mapping[str, Any]) -> None:
        for sink in self._sinks:
            try:
                sink.emit(payload)
            except Exception:
                # Observability is best-effort by design; crash containment wins.
                continue


class StructuredLogger:
    def __init__(self, component: str, sink: StructuredLogSink | None = None):
        self.component = str(component)
        self.sink = sink or CompositeLogSink((PythonLoggingSink(), StateLogSink()))

    def emit(
        self,
        event: str,
        *,
        level: str = "info",
        operation: str = "",
        status: str = "",
        correlation_id: str | None = None,
        **fields: Any,
    ) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": str(level).lower(),
            "event": str(event),
            "component": self.component,
            "operation": str(operation),
            "status": str(status),
            "correlation_id": correlation_id or current_correlation_id() or "",
        }
        payload.update({str(k): _redact(v, str(k)) for k, v in fields.items()})
        self.sink.emit(payload)
