"""Small lazy adapter around the optional :mod:`webview` dependency.

Keeping the import lazy means the existing Tkinter entrypoint and backend tests
do not require PyWebView until the dedicated WebView shell is actually started.
"""

from __future__ import annotations

import importlib
from typing import Any

from .exceptions import DesktopShellDependencyError


def load_webview() -> Any:
    try:
        return importlib.import_module("webview")
    except ModuleNotFoundError as exc:
        raise DesktopShellDependencyError(
            "PyWebView is required for the WebView shell. Install requirements-desktop.txt."
        ) from exc
