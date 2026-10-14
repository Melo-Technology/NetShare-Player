"""Stable, PyWebView-agnostic desktop API boundary."""

from .api import DesktopApi
from .contracts import ApiError, ApiMeta, ApiResponse

__all__ = ["ApiError", "ApiMeta", "ApiResponse", "DesktopApi"]
