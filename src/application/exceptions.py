"""Typed exceptions raised by the application service layer."""

from __future__ import annotations

from typing import Any

from .correlation import current_correlation_id


class ApplicationServiceError(RuntimeError):
    """Base error that is safe for DesktopApi to translate later."""

    default_code = "application_error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ):
        super().__init__(str(message))
        self.code = str(code or self.default_code)
        self.details = dict(details or {})
        self.correlation_id = correlation_id or current_correlation_id()

    def public_dict(self) -> dict[str, Any]:
        """Technical payload only; user-facing localization is added later."""
        return {
            "code": self.code,
            "correlation_id": self.correlation_id,
            "details": dict(self.details),
        }


class ApplicationValidationError(ApplicationServiceError):
    default_code = "validation_failed"


class ApplicationNotFoundError(ApplicationServiceError):
    default_code = "not_found"


class ApplicationConflictError(ApplicationServiceError):
    default_code = "conflict"


class ApplicationUnavailableError(ApplicationServiceError):
    default_code = "dependency_unavailable"


class ApplicationOperationError(ApplicationServiceError):
    default_code = "operation_failed"
