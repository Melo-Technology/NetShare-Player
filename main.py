"""
Application entry point.

This module performs the startup bootstrap for the server: it enforces a
single running instance, loads remote feature flags, prints dependency
warnings when optional packages are missing, and finally launches the Tkinter
GUI.
"""

from src.utils.platform import ensure_single_instance
from src.core.firebase import fetch_feature_flags
import src.state as state
from src.deps import HAS_WEBSOCKETS, HAS_WATCHDOG

if __name__ == "__main__":
    ensure_single_instance()

    flags = fetch_feature_flags()
    print(f"Flags fetched: {flags}")
    if flags:
        state.FEATURE_FLAGS.update(flags)

    if not HAS_WEBSOCKETS:
        print("WARNING: Module 'websockets' not found.")
        print("   Install it: pip install websockets")
        print("   Server will start in HTTP-only mode.\n")

    if not HAS_WATCHDOG:
        print("WARNING: Module 'watchdog' not found.")
        print("   Install it: pip install watchdog")
        print("   Live directory updates will be disabled.\n")

    from src.gui.app import App
    app = App()
    app.mainloop()