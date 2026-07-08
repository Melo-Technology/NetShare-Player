"""ServerLifecycleMixin extracted from the main GUI window."""

import math
import queue
import socket
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import tkinter as tk

import src.state as state
from src.constants import VERSION, DEFAULT_PORT, MAX_HISTORY, FONT_MONO
from src.deps import HAS_WEBSOCKETS, HAS_QRCODE, HAS_FIREBASE
from src.i18n import DEFAULT_LANGUAGE, LANGUAGES, set_language, t
from src.theme import _theme, BG, SURFACE, SURFACE2, BORDER, FG, FG2, FG3, DANGER
from src.core.firebase import start_polling, stop_polling
from src.utils.platform import PLATFORM
from src.utils.network import get_local_ips
from src.utils.sleep import inhibit_sleep
from src.core.file_index import _file_index, _start_watcher, _stop_watcher
from src.core.ws_manager import WebSocketManager, _run_ws_server
from src.core.tunnel import PublicTunnel
from src.routes.handler import NetShareHandler
from http.server import ThreadingHTTPServer


class ServerLifecycleMixin:

    # Server lifecycle

    def _toggle_server(self):
        if self._running:
            self._stop_server()
        else:
            self._start_server()


    def _start_server(self):
        folder = self._selected_folder.get()
        if not folder:
            messagebox.showwarning(t("no_folder_title"), t("no_folder_message"))
            return

        root = Path(folder).resolve()
        if not root.exists() or not root.is_dir():
            messagebox.showerror(t("invalid_folder_title"), t("invalid_folder_message", root=root))
            return

        try:
            port = int(self._port_var.get())
        except ValueError:
            messagebox.showerror(t("invalid_port_title"), t("invalid_port_message"))
            return

        state.ROOT_DIR       = root
        state.SERVER_NAME    = self._name_var.get() or socket.gethostname()
        state.LOCAL_PASSWORD = self._password_var.get().strip()
        allow_upload         = bool(self._allow_upload_var.get())
        allow_edit           = bool(self._allow_edit_var.get())
        write_enabled        = allow_upload or allow_edit
        state.COMMUNITY_PASSWORD = self._community_key_var.get().strip()
        state.ADMIN_PASSWORD = self._admin_key_var.get().strip()
        state.COMMUNITY_BROWSE_ROOT = bool(self._community_browse_root_var.get())
        state.COMMUNITY_DOWNLOAD = bool(self._community_download_var.get())
        state.COMMUNITY_UPLOAD = bool(self._community_upload_var.get())
        state.PUBLIC_UPLOAD_MODE = self._public_upload_mode_var.get()
        state.MAX_UPLOADS_PER_HOUR = max(1, int(self._max_uploads_var.get()))
        state.MAX_UPLOAD_SIZE_MB = max(1, int(self._max_size_var.get()))
        state.ALLOWED_UPLOAD_EXTENSIONS = self._selected_upload_extensions()
        state.save_public_config()

        # Respect remote flags; never enable a remotely disabled feature.
        remote_upload = self._remote_flags.get("upload")
        remote_edit   = self._remote_flags.get("document_edit")
        if remote_upload is False:
            allow_upload  = False
        if remote_edit is False:
            allow_edit    = False
        write_enabled = allow_upload or allow_edit

        state.FEATURE_FLAGS.update({
            "upload": allow_upload,
            "document_edit": allow_edit,
            "write_pairing": write_enabled,
        })
        write_otp = ""
        self._write_otp = write_otp
        _file_index.clear()
        self._clear_incoming()
        self._add_incoming_line(t("incoming_waiting"), "dim")

        state._log_callback = lambda msg, kind="info": None
        self._start_log_drainer()

        # Re-fetch remote flags in background each time server starts
        self._fetch_remote_flags_async()

        try:
            self._server = ThreadingHTTPServer(("0.0.0.0", port), NetShareHandler)
            self._server.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024
            )
        except OSError as e:
            messagebox.showerror(t("port_error_title"), t("port_error_message", port=port, error=e))
            return

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        _file_index.build(state.ROOT_DIR)
        _start_watcher(state.ROOT_DIR)
        _file_index.start_periodic_flush(state.ROOT_DIR)

        ws_port = port + 1
        if HAS_WEBSOCKETS:
            state._ws_manager = WebSocketManager()
            self._ws_thread = threading.Thread(
                target=_run_ws_server,
                args=("0.0.0.0", ws_port, state._ws_manager),
                daemon=True,
            )
            self._ws_thread.start()
        else:
            state._ws_manager = None
            self._log("websockets not installed - persistent connection disabled", "dim")
            self._log("->  pip install websockets", "dim")

        self._running = True
        self._log(f"HTTP   :{port}   running", "ok")
        if HAS_WEBSOCKETS:
            self._log(f"WS     :{ws_port}   running", "ok")
        self._log(f"ROOT   {root}", "info")
        self._log(
            "AUTH   local password set" if state.LOCAL_PASSWORD
            else "AUTH   no local password (open LAN access)",
            "ok" if state.LOCAL_PASSWORD else "dim",
        )
        self._log(
            f"WRITE  upload={'on' if allow_upload else 'off'}  edit={'on' if allow_edit else 'off'}",
            "ok" if write_enabled else "dim",
        )
        if write_enabled:
            self._log("WRITE  local trusted-device pairing enabled", "ok")

        self._toggle_btn.configure(text=t("stop_server"), bg=DANGER())
        self._add_hover(self._toggle_btn, DANGER(), "#991111",
                        text_normal=FG(), text_hover=FG())
        self._toggle_btn.configure(fg=FG())
        self._status_canvas.itemconfig(self._status_dot_id, fill="#22cc44")
        self._status_lbl.configure(text=t("online"), fg=FG())
        self._set_write_options_enabled(False)
        self._update_addr_block(port, ws_port if HAS_WEBSOCKETS else None)
        self._draw_write_pairing_active()
        self._show_sleep_btn()
        self._draw_public_ready()
        self.after(100, lambda: self._canvas.yview_moveto(1.0))


    def _stop_server(self):
        if self._tunnel_active or self._tunnel:
            self._stop_tunnel()

        if state._ws_manager:
            state._ws_manager.notify_server_stopping()
            state._ws_manager = None

        _file_index.flush_if_dirty(state.ROOT_DIR)
        _file_index.clear()
        _stop_watcher()

        if self._server:
            threading.Thread(target=self._server.shutdown, daemon=True).start()
            self._server = None

        self._ws_thread         = None
        self._running           = False
        state._log_callback     = None
        state.LOCAL_PASSWORD    = ""
        state.TUNNEL_PASSWORD   = ""
        state.TUNNEL_ACTIVE     = False
        state.clear_write_auth()
        self._write_otp = ""
        state.FEATURE_FLAGS.update({
            "upload": False,
            "document_edit": False,
            "write_pairing": False,
        })

        self._stop_log_drainer()
        self._log("server stopped", "dim")
        self._toggle_btn.configure(text=t("start_server"), bg=FG(), fg=BG())
        self._add_hover(self._toggle_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())
        self._status_canvas.itemconfig(self._status_dot_id, fill=FG3())
        self._status_lbl.configure(text=t("offline"), fg=FG3())
        self._set_write_options_enabled(True)
        self._draw_offline_placeholder()
        self._draw_write_pairing_placeholder()
        self._draw_public_offline_placeholder()
        self._hide_sleep_btn()

    # Tunnel lifecycle


    # Tunnel lifecycle

    def _start_tunnel(self):
        if not self._running:
            messagebox.showwarning(t("netshare_title"), t("start_server_first"))
            return
        if self._tunnel_active:
            return

        folder    = self._selected_folder.get()
        confirmed = messagebox.askyesno(
            t("security_title"),
            t("security_message", folder=folder),
            icon="warning", default="no",
        )
        if not confirmed:
            return

        self._rotate_public_keys()
        state.COMMUNITY_PASSWORD = self._community_key_var.get().strip()
        state.ADMIN_PASSWORD = self._admin_key_var.get().strip()
        state.COMMUNITY_BROWSE_ROOT = bool(self._community_browse_root_var.get())
        state.COMMUNITY_DOWNLOAD = bool(self._community_download_var.get())
        state.COMMUNITY_UPLOAD = bool(self._community_upload_var.get())
        state.PUBLIC_UPLOAD_MODE = self._public_upload_mode_var.get()
        state.MAX_UPLOADS_PER_HOUR = max(1, int(self._max_uploads_var.get()))
        state.MAX_UPLOAD_SIZE_MB = max(1, int(self._max_size_var.get()))
        state.ALLOWED_UPLOAD_EXTENSIONS = self._selected_upload_extensions()
        state.save_public_config()

        self._tunnel_pw       = state.ADMIN_PASSWORD
        state.TUNNEL_PASSWORD = state.ADMIN_PASSWORD
        state.TUNNEL_ACTIVE   = True

        try:
            port = int(self._port_var.get())
        except ValueError:
            port = DEFAULT_PORT

        self._tunnel_active = True
        self._draw_public_connecting()

        self._tunnel = PublicTunnel(port=port)
        self._tunnel.start(
            on_url=self._on_tunnel_url,
            on_error=self._on_tunnel_error,
            on_stop=self._on_tunnel_stopped,
            on_reconnecting=self._on_tunnel_reconnecting,
        )


    def _stop_tunnel(self):
        if self._tunnel:
            self._tunnel.stop()
            self._tunnel = None
        self._tunnel_active   = False
        self._tunnel_url      = ""
        self._tunnel_pw       = ""
        state.TUNNEL_PASSWORD = ""
        state.TUNNEL_ACTIVE   = False
        self._draw_public_ready()
        self._log("TUNNEL stopped", "dim")


    def _on_tunnel_url(self, url: str):
        self._tunnel_url = url
        self.after(0, lambda: self._draw_public_active(url))
        self.after(0, lambda: self._log(f"TUNNEL live -> {url}", "ok"))
        self.after(100, lambda: self._canvas.yview_moveto(1.0))


    def _on_tunnel_error(self, msg: str):
        self._tunnel_active = False
        self.after(0, lambda: self._draw_public_error(msg))
        self.after(0, lambda: self._log(f"TUNNEL error: {msg}", "error"))


    def _on_tunnel_stopped(self):
        pass   # tunnel auto-reconnects; UI feedback via on_reconnecting


    def _on_tunnel_reconnecting(self, delay: int, attempt: int):
        self.after(0, lambda: self._draw_public_reconnecting(delay, attempt))
        self.after(0, lambda: self._log(
            f"TUNNEL lost - reconnecting in {delay}s (attempt {attempt})", "dim"
        ))

    # Window close


    # Window close

    def _on_close(self):
        stop_polling()
        if self._tunnel_active or self._tunnel:
            self._stop_tunnel()
        if self._sleep_inhibit_enabled:
            inhibit_sleep(False)
        if self._running:
            self._stop_server()
        self.destroy()

