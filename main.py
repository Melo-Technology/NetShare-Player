"""
NetShare Player — Entry point
=============================
Run:  python main.py

All logic lives under src/. This file only guards single-instance,
prints optional dependency warnings, then launches the GUI.
"""

from src.utils.platform import ensure_single_instance
from src.deps import HAS_WEBSOCKETS, HAS_WATCHDOG


if __name__ == "__main__":
    ensure_single_instance()

    if not HAS_WEBSOCKETS:
        print("⚠  Module 'websockets' not found.")
        print("   Install it: pip install websockets")
        print("   Server will start in HTTP-only mode.\n")

    if not HAS_WATCHDOG:
        print("⚠  Module 'watchdog' not found.")
        print("   Install it: pip install watchdog")
        print("   Live directory updates will be disabled.\n")

    from src.gui.app import App
    app = App()
    app.mainloop()
