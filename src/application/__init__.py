"""Application-layer façade for desktop UI migrations.

This package deliberately sits above the existing ``src.state`` / ``src.core``
implementation.  It does not replace the HTTP protocol or persistence layer;
it exposes stable, UI-agnostic services and serializable DTOs that future
frontends can consume.
"""

from .correlation import correlation_scope, current_correlation_id, new_correlation_id
from .exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationOperationError,
    ApplicationServiceError,
    ApplicationUnavailableError,
    ApplicationValidationError,
)
from .services import ApplicationServices, build_application_services

__all__ = [
    "ApplicationConflictError",
    "ApplicationNotFoundError",
    "ApplicationOperationError",
    "ApplicationServiceError",
    "ApplicationServices",
    "ApplicationUnavailableError",
    "ApplicationValidationError",
    "build_application_services",
    "correlation_scope",
    "current_correlation_id",
    "new_correlation_id",
]
