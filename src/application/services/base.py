"""Base class providing structured logging and exception containment."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, TypeVar

from ..correlation import correlation_scope
from ..exceptions import ApplicationOperationError, ApplicationServiceError, ApplicationValidationError
from ..observability import StructuredLogger

_T = TypeVar("_T")


class BaseApplicationService:
    service_name = "application"

    def __init__(self, logger: StructuredLogger | None = None):
        self.log = logger or StructuredLogger(type(self).__name__)
        self.log.emit(
            "service.initialized", operation="initialize", status="success",
            service=self.service_name,
        )

    def _execute(
        self,
        operation: str,
        callback: Callable[[], _T],
        *,
        correlation_id: str | None = None,
    ) -> _T:
        with correlation_scope(correlation_id) as cid:
            started = time.monotonic()
            self.log.emit(
                "service.called", operation=operation, status="started",
                correlation_id=cid, service=self.service_name,
            )
            try:
                result = callback()
            except ApplicationServiceError as error:
                self.log.emit(
                    "service.failed", level="error", operation=operation,
                    status="failed", correlation_id=cid, service=self.service_name,
                    error_type=type(error).__name__, error_code=error.code,
                    duration_ms=round((time.monotonic() - started) * 1000, 3),
                )
                raise
            except ValueError as error:
                wrapped = ApplicationValidationError(
                    f"{self.service_name}.{operation} validation failed",
                    code=f"{self.service_name}.{operation}.validation_failed",
                    correlation_id=cid,
                )
                self.log.emit(
                    "settings.validation_failed" if self.service_name == "settings" else "service.validation_failed",
                    level="warning", operation=operation, status="rejected",
                    correlation_id=cid, service=self.service_name,
                    error_type=type(error).__name__, error_code=wrapped.code,
                    duration_ms=round((time.monotonic() - started) * 1000, 3),
                )
                self.log.emit(
                    "service.failed", level="error", operation=operation,
                    status="failed", correlation_id=cid, service=self.service_name,
                    error_type=type(error).__name__, error_code=wrapped.code,
                    duration_ms=round((time.monotonic() - started) * 1000, 3),
                )
                raise wrapped from error
            except Exception as error:
                wrapped = ApplicationOperationError(
                    f"{self.service_name}.{operation} failed",
                    code=f"{self.service_name}.{operation}.failed",
                    correlation_id=cid,
                )
                self.log.emit(
                    "service.failed", level="error", operation=operation,
                    status="failed", correlation_id=cid, service=self.service_name,
                    error_type=type(error).__name__, error_code=wrapped.code,
                    duration_ms=round((time.monotonic() - started) * 1000, 3),
                )
                raise wrapped from error
            self.log.emit(
                "service.completed", operation=operation, status="success",
                correlation_id=cid, service=self.service_name,
                duration_ms=round((time.monotonic() - started) * 1000, 3),
            )
            return result

    def _validation_error(
        self,
        operation: str,
        error: ApplicationServiceError,
        *,
        field: str = "",
        correlation_id: str | None = None,
    ) -> None:
        with correlation_scope(correlation_id) as cid:
            self.log.emit(
                "settings.validation_failed" if self.service_name == "settings" else "service.validation_failed",
                level="warning", operation=operation, status="rejected",
                correlation_id=cid, service=self.service_name, field=field, error_code=error.code,
            )
            if not error.correlation_id:
                error.correlation_id = cid
            raise error
