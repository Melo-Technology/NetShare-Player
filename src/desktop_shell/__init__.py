"""PyWebView desktop shell composition layer.

Step 05 only: this package composes the frozen DesktopApi and UiEventBus with
PyWebView.  It contains no business screens and never accesses src.state,
src.core, HTTP routes, or Tkinter directly.
"""

from .bridge import ShellBridge
from .event_forwarder import WebViewEventForwarder
from .runtime import DesktopShellRuntime, run_desktop_shell

__all__ = [
    "DesktopShellRuntime",
    "ShellBridge",
    "WebViewEventForwarder",
    "run_desktop_shell",
]
