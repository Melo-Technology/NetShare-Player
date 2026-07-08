"""
Main Tkinter application window for NetShare Server.

App composes the GUI mixins, owns server and tunnel lifecycle state, drains log
messages onto the UI thread, and starts Firebase Remote Config polling after the
window is ready.
"""

import socket
from pathlib import Path

import tkinter as tk

import src.state as state
from src.constants import DEFAULT_PORT
from src.core.firebase import start_polling
from src.core.tunnel import PublicTunnel
from src.gui.actions import ActionsMixin
from src.gui.config_section import ConfigSectionMixin
from src.gui.header_section import HeaderSectionMixin
from src.gui.layout import LayoutMixin
from src.gui.log_panel import LogPanelMixin
from src.gui.pairing_panel import PairingPanelMixin
from src.gui.public_access_key import PublicAccessKeyMixin
from src.gui.public_panel import PublicPanelMixin
from src.gui.remote_flags import RemoteFlagsMixin
from src.gui.server_lifecycle import ServerLifecycleMixin
from src.gui.theme_mixin import ThemeMixin
from src.i18n import DEFAULT_LANGUAGE
from src.theme import _theme, _DARK, BG
from src.utils.platform import PLATFORM


class App(
    ThemeMixin,
    LayoutMixin,
    HeaderSectionMixin,
    ConfigSectionMixin,
    RemoteFlagsMixin,
    PairingPanelMixin,
    PublicPanelMixin,
    PublicAccessKeyMixin,
    LogPanelMixin,
    ActionsMixin,
    ServerLifecycleMixin,
    tk.Tk,
):

    def __init__(self):
        super().__init__()
        self.title("NETSHARE PLAYER")

        # Theme
        self._dark_mode = True
        _theme.update(_DARK)

        # DPI / scale
        try:
            raw_scale    = self.tk.call("tk", "scaling")
            self._ui_scale = max(1.0, raw_scale / 1.3333)
        except Exception:
            self._ui_scale = 1.0

        if PLATFORM == "linux":
            import os
            for ev in ("GDK_SCALE", "QT_SCALE_FACTOR"):
                try:
                    v = float(os.environ.get(ev, ""))
                    if v > self._ui_scale:
                        self._ui_scale = v
                except (ValueError, TypeError):
                    pass

        self._ui_scale = min(max(self._ui_scale, 1.0), 3.0)
        self._win_w    = int(480 * self._ui_scale)
        self._win_h    = int(700 * self._ui_scale)

        self.configure(bg=BG())
        self.resizable(True, True)
        self.minsize(self._win_w, int(500 * self._ui_scale))

        # Server state
        self._server    = None
        self._thread    = None
        self._running   = False
        self._ws_thread = None

        # Sleep inhibitor
        self._sleep_inhibit_enabled = False

        # Tunnel state
        self._tunnel:         PublicTunnel | None = None
        self._tunnel_active   = False
        self._tunnel_url      = ""
        self._tunnel_pw       = ""
        self._public_btn      = None
        self._public_section  = None

        # Remote flag cache (mirrors last fetch)
        # True  = feature enabled remotely   False = disabled remotely
        # None  = not yet fetched (show everything by default)
        self._remote_flags: dict[str, bool | None] = {
            "upload":        None,
            "document_edit": None,
        }

        # Tkinter variables
        self._selected_folder  = tk.StringVar(value="")
        self._port_var         = tk.StringVar(value=str(DEFAULT_PORT))
        self._name_var         = tk.StringVar(value=socket.gethostname())
        self._password_var     = tk.StringVar(value="")
        self._language_var     = tk.StringVar(value=DEFAULT_LANGUAGE)
        self._allow_upload_var = tk.BooleanVar(value=False)
        self._allow_edit_var   = tk.BooleanVar(value=False)
        self._write_option_widgets: list = []
        self._write_otp         = ""
        self._community_key_var = tk.StringVar(value=state.COMMUNITY_PASSWORD)
        self._admin_key_var     = tk.StringVar(value=state.ADMIN_PASSWORD)
        self._community_browse_root_var = tk.BooleanVar(value=state.COMMUNITY_BROWSE_ROOT)
        self._community_download_var = tk.BooleanVar(value=state.COMMUNITY_DOWNLOAD)
        self._community_upload_var = tk.BooleanVar(value=state.COMMUNITY_UPLOAD)
        self._public_upload_mode_var = tk.StringVar(value=state.PUBLIC_UPLOAD_MODE)
        self._max_uploads_var   = tk.IntVar(value=state.MAX_UPLOADS_PER_HOUR)
        self._max_size_var      = tk.IntVar(value=state.MAX_UPLOAD_SIZE_MB)
        self._upload_type_vars = {
            "images": tk.BooleanVar(value=bool(state.ALLOWED_UPLOAD_EXTENSIONS & {".jpg", ".jpeg", ".png", ".gif", ".webp"})),
            "video": tk.BooleanVar(value=bool(state.ALLOWED_UPLOAD_EXTENSIONS & {".mp4", ".mov", ".mkv", ".avi", ".webm"})),
            "audio": tk.BooleanVar(value=bool(state.ALLOWED_UPLOAD_EXTENSIONS & {".mp3", ".wav", ".flac", ".aac", ".m4a"})),
            "documents": tk.BooleanVar(value=bool(state.ALLOWED_UPLOAD_EXTENSIONS & {".txt", ".md", ".pdf", ".doc", ".docx", ".xls", ".xlsx"})),
            "archives": tk.BooleanVar(value=bool(state.ALLOWED_UPLOAD_EXTENSIONS & {".zip", ".rar", ".7z", ".tar", ".gz"})),
        }
        self._folder_history: list[str] = []

        # Icon
        icon_path = Path(__file__).parent.parent.parent / "favicon.ico"
        if icon_path.exists():
            try:
                self.iconbitmap(str(icon_path))
            except Exception:
                pass

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.update_idletasks()
        w = self.winfo_width(); h = self.winfo_height()
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{self._win_w}x{self._win_h}+{x}+{y}")

        # Fetch remote flags shortly after launch (non-blocking)
        self.after(500, self._fetch_remote_flags_async)
        start_polling(lambda flags: self.after(0, lambda: self._apply_remote_flags(flags)))

    # Scale helpers

    def _s(self, v: int) -> int:
        return int(v * self._ui_scale)

    def _fs(self, v: int) -> int:
        return v if PLATFORM == "mac" else max(1, int(v * self._ui_scale))
