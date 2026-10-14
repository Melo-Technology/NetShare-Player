"""Map technical GUI failures to localizable keys and safe diagnostics."""

from __future__ import annotations

import logging
from dataclasses import dataclass

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class GuiError:
    title_key: str
    message_key: str
    support_code: str
    log_code: str


_GUI_ERRORS = {
    "server_start": GuiError(
        "port_error_title", "port_error_message_safe", "SYS-02", "server.start_failed"
    ),
    "service_unavailable": GuiError(
        "service_error_title", "service_unavailable_safe", "SYS-03", "service.unavailable"
    ),
    "startup": GuiError(
        "startup_error_title", "splash_startup_error_safe", "SYS-01", "startup.failed"
    ),
    "tunnel": GuiError(
        "tunnel_error_title", "tunnel_error_safe", "NET-03", "tunnel.failed"
    ),
}


def map_gui_error(kind: str) -> GuiError:
    mapped = _GUI_ERRORS.get(kind)
    if mapped is None:
        _LOGGER.warning("Unknown GUI error kind %r; using startup fallback", kind)
        return _GUI_ERRORS["startup"]
    return mapped


def sanitized_diagnostic(error: BaseException) -> str:
    return type(error).__name__
