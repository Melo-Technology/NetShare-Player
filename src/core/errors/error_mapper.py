"""Map server failures to stable, non-localized API error metadata."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class ErrorSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ErrorDomain(str, Enum):
    AUTH = "auth"
    CLOUD = "cloud"
    NETWORK = "network"
    PERMISSION = "permission"
    SECURITY = "security"
    STORAGE = "storage"
    STREAMING = "streaming"
    TRANSFER = "transfer"
    VALIDATION = "validation"
    SYSTEM = "system"


@dataclass(frozen=True)
class ApiError:
    error: str
    code: str
    domain: ErrorDomain
    severity: ErrorSeverity = ErrorSeverity.ERROR
    support_code: str | None = None

    def payload(self) -> dict[str, str]:
        result = {
            "error": self.error,
            "code": self.code,
            "domain": self.domain.value,
            "severity": self.severity.value,
        }
        if self.support_code:
            result["support_code"] = self.support_code
        return result


_SUPPORT_PREFIX = {
    ErrorDomain.AUTH: "AUTH",
    ErrorDomain.CLOUD: "CLOUD",
    ErrorDomain.NETWORK: "NET",
    ErrorDomain.PERMISSION: "PERM",
    ErrorDomain.SECURITY: "SEC",
    ErrorDomain.STORAGE: "STOR",
    ErrorDomain.STREAMING: "STRM",
    ErrorDomain.TRANSFER: "XFER",
    ErrorDomain.VALIDATION: "VAL",
    ErrorDomain.SYSTEM: "SYS",
}

_FALLBACK_CODES = {
    ErrorDomain.AUTH: "auth.unexpected",
    ErrorDomain.CLOUD: "cloud.unexpected",
    ErrorDomain.NETWORK: "network.unexpected",
    ErrorDomain.PERMISSION: "permission.unexpected",
    ErrorDomain.SECURITY: "security.unexpected",
    ErrorDomain.STORAGE: "storage.unexpected",
    ErrorDomain.STREAMING: "streaming.unexpected",
    ErrorDomain.TRANSFER: "transfer.unexpected",
    ErrorDomain.VALIDATION: "validation.unexpected",
    ErrorDomain.SYSTEM: "system.unexpected",
}

_MACHINE_CODES = {
    "premium_locked": ("permission.premium_locked", ErrorDomain.PERMISSION, "PERM-02"),
    "ffmpeg_unavailable": ("streaming.ffmpeg_unavailable", ErrorDomain.STREAMING, "STRM-01"),
    "ffmpeg_memory_limit": ("streaming.memory_limit", ErrorDomain.STREAMING, "STRM-04"),
}


def _infer_domain(error: str, status: int) -> ErrorDomain:
    """Best-effort classification for untyped legacy errors only.

    This heuristic is not a stable API contract: callers that expose a domain
    or code to consumers must pass explicit values or register a machine code.
    Fallback codes remain fixed constants even if this classification changes.
    """
    lowered = error.lower()
    if status in (401, 403):
        return ErrorDomain.AUTH if "auth" in lowered or "credential" in lowered else ErrorDomain.PERMISSION
    if any(word in lowered for word in ("upload", "transfer", "chunk", "manifest")):
        return ErrorDomain.TRANSFER
    if any(word in lowered for word in ("hls", "ffmpeg", "stream", "thumbnail", "waveform")):
        return ErrorDomain.STREAMING
    if any(word in lowered for word in ("cloud", "provider", "dropbox", "drive", "mega")):
        return ErrorDomain.CLOUD
    if status == 404 or any(word in lowered for word in ("file", "folder", "path", "storage")):
        return ErrorDomain.STORAGE
    if status in (400, 409, 413, 415, 422):
        return ErrorDomain.VALIDATION
    if status in (429, 502, 503, 504):
        return ErrorDomain.NETWORK
    return ErrorDomain.SYSTEM


def _coerce_domain(value: ErrorDomain | str | None) -> ErrorDomain | None:
    if value is None:
        return None
    try:
        return ErrorDomain(value)
    except (TypeError, ValueError):
        return ErrorDomain.SYSTEM


def _coerce_severity(value: ErrorSeverity | str) -> ErrorSeverity:
    try:
        return ErrorSeverity(value)
    except (TypeError, ValueError):
        return ErrorSeverity.ERROR


def map_api_error(
    error: str, *, status: int = 400, code: str | None = None,
    domain: ErrorDomain | str | None = None,
    severity: ErrorSeverity | str = ErrorSeverity.ERROR,
    support_code: str | None = None,
) -> ApiError:
    """Return additive metadata while preserving error byte-for-byte."""
    machine = _MACHINE_CODES.get(error)
    explicit_domain = _coerce_domain(domain)
    resolved_domain = explicit_domain if explicit_domain is not None else (
        machine[1] if machine else _infer_domain(error, status)
    )
    resolved_code = code or (
        machine[0] if machine else _FALLBACK_CODES[resolved_domain]
    )
    resolved_support = support_code or (
        machine[2] if machine else f"{_SUPPORT_PREFIX[resolved_domain]}-01"
    )
    return ApiError(
        error, resolved_code, resolved_domain, _coerce_severity(severity), resolved_support
    )


def enrich_error_payload(
    payload: Mapping[str, object], *, status: int = 400
) -> dict[str, object]:
    """Add metadata to an existing response without replacing fields."""
    result = dict(payload)
    error = result.get("error")
    if not isinstance(error, str):
        return result
    mapped = map_api_error(
        error, status=status,
        code=result.get("code") if isinstance(result.get("code"), str) else None,
        domain=result.get("domain") if isinstance(result.get("domain"), str) else None,
        severity=result.get("severity") if isinstance(result.get("severity"), str) else ErrorSeverity.ERROR,
        support_code=result.get("support_code") if isinstance(result.get("support_code"), str) else None,
    )
    # Normalize enum-backed fields even when a legacy payload supplied an
    # invalid string. Other existing fields remain additive and untouched.
    result["domain"] = mapped.domain.value
    result["severity"] = mapped.severity.value
    for key, value in mapped.payload().items():
        result.setdefault(key, value)
    return result
