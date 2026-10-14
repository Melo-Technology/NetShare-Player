"""Typed event contracts for the backend-only UI event bus.

The event model is deliberately JSON-native so a later frontend bridge can forward event
objects without custom encoders.  This module defines contracts only and does not attach producers to runtime sources.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
from typing import Any, Literal, TypedDict, cast

from .exceptions import EventPayloadValidationError, UnknownEventError

EventName = Literal[
    "server.status.changed",
    "server.addresses.changed",
    "devices.changed",
    "sharing.changed",
    "settings.changed",
    "metrics.updated",
    "activity.appended",
    "toast.requested",
]

SERVER_STATUS_CHANGED: EventName = "server.status.changed"
SERVER_ADDRESSES_CHANGED: EventName = "server.addresses.changed"
DEVICES_CHANGED: EventName = "devices.changed"
SHARING_CHANGED: EventName = "sharing.changed"
SETTINGS_CHANGED: EventName = "settings.changed"
METRICS_UPDATED: EventName = "metrics.updated"
ACTIVITY_APPENDED: EventName = "activity.appended"
TOAST_REQUESTED: EventName = "toast.requested"

EVENT_NAMES: frozenset[str] = frozenset(
    {
        SERVER_STATUS_CHANGED,
        SERVER_ADDRESSES_CHANGED,
        DEVICES_CHANGED,
        SHARING_CHANGED,
        SETTINGS_CHANGED,
        METRICS_UPDATED,
        ACTIVITY_APPENDED,
        TOAST_REQUESTED,
    }
)


class ServerStatusChangedPayload(TypedDict):
    running: bool


class ServerAddressesChangedPayload(TypedDict):
    addresses: list[str]


class DevicesChangedPayload(TypedDict):
    reason: str


class SharingChangedPayload(TypedDict):
    reason: str


class SettingsChangedPayload(TypedDict):
    section: str


class MetricsUpdatedPayload(TypedDict):
    metrics: dict[str, Any]


class ActivityAppendedPayload(TypedDict):
    activity: dict[str, Any]


class ToastRequestedPayload(TypedDict, total=False):
    level: Literal["success", "info", "warning", "error"]
    message_key: str
    params: dict[str, Any]


class UiEvent(TypedDict):
    name: EventName
    payload: dict[str, Any]
    correlation_id: str
    published_at: str
    sequence: int


def _require_string(payload: Mapping[str, Any], key: str) -> None:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise EventPayloadValidationError(f"{key} must be a non-empty string")


def _validate_json_native(value: Any, *, path: str = "payload") -> None:
    """Reject objects that need implicit/custom JSON conversion.

    ``json.dumps`` accepts a few Python conveniences such as tuples.  The bus contract is
    stricter: only the JSON-native primitives used by the Desktop API are accepted.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EventPayloadValidationError(f"{path} contains a non-finite float")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_native(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EventPayloadValidationError(f"{path} contains a non-string object key")
            _validate_json_native(item, path=f"{path}.{key}")
        return
    raise EventPayloadValidationError(
        f"{path} contains unsupported type {type(value).__name__}"
    )


def validate_event_payload(event_name: str, payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate and return a detached JSON-native payload dictionary."""
    if event_name not in EVENT_NAMES:
        raise UnknownEventError(f"unknown UI event: {event_name}")
    if payload is None:
        candidate: dict[str, Any] = {}
    elif isinstance(payload, Mapping):
        candidate = dict(payload)
    else:
        raise EventPayloadValidationError("payload must be a mapping")

    _validate_json_native(candidate)

    if event_name == SERVER_STATUS_CHANGED:
        if not isinstance(candidate.get("running"), bool):
            raise EventPayloadValidationError("running must be a bool")
    elif event_name == SERVER_ADDRESSES_CHANGED:
        addresses = candidate.get("addresses")
        if not isinstance(addresses, list) or not all(isinstance(item, str) for item in addresses):
            raise EventPayloadValidationError("addresses must be a list of strings")
    elif event_name in {DEVICES_CHANGED, SHARING_CHANGED}:
        _require_string(candidate, "reason")
    elif event_name == SETTINGS_CHANGED:
        _require_string(candidate, "section")
    elif event_name == METRICS_UPDATED:
        if not isinstance(candidate.get("metrics"), dict):
            raise EventPayloadValidationError("metrics must be an object")
    elif event_name == ACTIVITY_APPENDED:
        if not isinstance(candidate.get("activity"), dict):
            raise EventPayloadValidationError("activity must be an object")
    elif event_name == TOAST_REQUESTED:
        level = candidate.get("level")
        if level not in {"success", "info", "warning", "error"}:
            raise EventPayloadValidationError("level must be success, info, warning, or error")
        _require_string(candidate, "message_key")
        if "params" in candidate and not isinstance(candidate["params"], dict):
            raise EventPayloadValidationError("params must be an object")

    # Explicitly prove the final object serializes without a custom encoder.
    try:
        json.dumps(candidate, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EventPayloadValidationError("payload is not JSON serializable") from exc
    return candidate


def as_event_name(value: str) -> EventName:
    if value not in EVENT_NAMES:
        raise UnknownEventError(f"unknown UI event: {value}")
    return cast(EventName, value)
