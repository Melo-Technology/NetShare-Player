"""Canonical NetShare Server desktop entrypoint.

Step 15 completed the desktop UI migration: the application now starts the
PyWebView shell directly.  All business/server logic remains behind the
Application Services -> DesktopApi -> UiEventBus boundaries established during
the migration.
"""

from __future__ import annotations

import os

from src.desktop_shell import run_desktop_shell
from src.runtime.logging_runtime import install_activity_logging_bridge
from src.utils.platform import ensure_single_instance


def main() -> None:
    """Start the single-instance native PyWebView desktop application."""
    ensure_single_instance()
    install_activity_logging_bridge()
    debug = os.environ.get("NETSHARE_WEBVIEW_DEBUG", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    run_desktop_shell(debug=debug)


if __name__ == "__main__":
    main()
