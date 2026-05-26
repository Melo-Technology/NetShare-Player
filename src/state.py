"""
NetShare Player — Global runtime state
All mutable singletons that need to be shared across modules live here.
Other modules import this module by reference (import src.state as state)
to ensure they always read the *current* value of each variable.
"""

import queue
import socket
from pathlib import Path

# == Server / directory state ===================================================

ROOT_DIR:        Path = Path.cwd()
SERVER_NAME:     str  = socket.gethostname()
LOCAL_PASSWORD:  str  = ""   # password for LAN clients
TUNNEL_PASSWORD: str  = ""   # password for public-tunnel clients
TUNNEL_ACTIVE:   bool = False

# == Log pipeline ===============================================================
# _log_callback is set to a no-op lambda while the server is running so that
# _emit() stops calling print(); the GUI drains _log_queue via a Tkinter timer.

_log_queue:    queue.Queue = queue.Queue()
_log_callback              = None        # set by App._start_server


def _emit(msg: str, kind: str = "info"):
    """Put a log entry on the queue; also print when no GUI is attached."""
    _log_queue.put((msg, kind))
    if not _log_callback:
        print(msg)


# == Runtime singletons (set/cleared by App) ====================================
# These are mutable references; always access via  state._ws_manager  etc.

_ws_manager  = None   # core.websocket_manager.WebSocketManager | None
