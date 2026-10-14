"""JSON-native response contracts exposed by :mod:`src.desktop_api`.

The DesktopApi boundary deliberately returns plain ``dict`` / ``list`` /
primitive values only.  No dataclass, enum, pathlib object, runtime object or
custom JSON encoder is required by a future desktop shell.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict


class ApiMeta(TypedDict):
    correlation_id: str


class ApiError(TypedDict):
    code: str
    category: Literal[
        "validation",
        "not_found",
        "conflict",
        "unavailable",
        "operation",
        "internal",
        "serialization",
    ]
    message_key: str
    details: dict[str, Any]


class ApiResponse(TypedDict):
    ok: bool
    data: Any
    error: ApiError | None
    meta: ApiMeta
