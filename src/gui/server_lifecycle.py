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

PUBLIC_HTTP_PORT_OFFSET = 2


class ServerLifecycleMixin:

    # Server lifecycle

    def _toggle_server(self):
        if self._running:
            self._stop_server()
        else:
            self._start_server()

    def _focus_password_setting(self, *, select_all=False):
        """Focus the password editor wherever the current layout exposes it."""
        entry = getattr(self, "_pw_entry", None)
        if entry is not None:
            try:
                if entry.winfo_exists():
                    entry.focus_set()
                    if select_all:
                        entry.selection_range(0, "end")
                    return
            except tk.TclError:
                pass

        # The compact layout moved this field into Settings > Permissions.
        self._settings_active_key = "permissions"
        self._open_settings_modal()

        def _focus_modal_entry():
            modal_entry = getattr(self, "_settings_password_entry", None)
            try:
                if modal_entry is not None and modal_entry.winfo_exists():
                    modal_entry.focus_set()
                    if select_all:
                        modal_entry.selection_range(0, "end")
            except tk.TclError:
                pass

        self.after(50, _focus_modal_entry)


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

        requested_password = self._password_var.get().strip()
        if requested_password == state.SAVED_LOCAL_PASSWORD and state.password_reminder_due():
            change_password = messagebox.askyesno(
                t("password_reminder_title"),
                t("password_reminder_message", days=state.PASSWORD_REMINDER_DAYS),
                icon="question",
            )
            if change_password:
                self._focus_password_setting(select_all=True)
                return
            state.postpone_password_reminder()
        if not requested_password:
            continue_open = messagebox.askyesno(
                t("no_password_warning_title"),
                t("no_password_warning_message"),
                icon="warning", default="no",
            )
            if not continue_open:
                self._focus_password_setting()
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
            self._server.is_public_listener = False
            self._public_server = ThreadingHTTPServer(
                ("127.0.0.1", port + PUBLIC_HTTP_PORT_OFFSET), NetShareHandler
            )
            self._public_server.is_public_listener = True
            self._server.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024
            )
        except OSError as e:
            if getattr(self, "_public_server", None):
                self._public_server.server_close()
                self._public_server = None
            if getattr(self, "_server", None):
                self._server.server_close()
                self._server = None
            messagebox.showerror(t("port_error_title"), t("port_error_message", port=port, error=e))
            return

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._public_thread = threading.Thread(
            target=self._public_server.serve_forever,
            daemon=True,
            name="netshare-public-http",
        )
        self._public_thread.start()
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
        state.record_folder_share(str(root))
        self._folder_history = [item["path"] for item in reversed(state.FOLDER_SHARE_HISTORY)]
        self._refresh_history()
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
        self._advertised_ips = tuple(get_local_ips())
        self._schedule_network_monitor()
        self._draw_write_pairing_active()
        self._show_sleep_btn()
        self._draw_public_ready()


    def _stop_server(self):
        if self._network_monitor_job is not None:
            self.after_cancel(self._network_monitor_job)
            self._network_monitor_job = None
        self._advertised_ips = ()

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
        if getattr(self, "_public_server", None):
            threading.Thread(
                target=self._public_server.shutdown, daemon=True
            ).start()
            self._public_server = None

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

    def _schedule_network_monitor(self):
        if self._network_monitor_job is not None:
            self.after_cancel(self._network_monitor_job)
        self._network_monitor_job = self.after(2000, self._check_network_address)

    def _check_network_address(self):
        self._network_monitor_job = None
        if not self._running:
            return

        current_ips = tuple(get_local_ips())
        if current_ips != self._advertised_ips:
            old_ips = self._advertised_ips
            self._advertised_ips = current_ips
            try:
                port = int(self._port_var.get())
            except ValueError:
                port = DEFAULT_PORT
            ws_port = port + 1 if HAS_WEBSOCKETS else None
            self._update_addr_block(port, ws_port)
            self._log(
                f"NETWORK address changed: {', '.join(old_ips) or '-'} -> "
                f"{', '.join(current_ips)}",
                "info",
            )
            if state._ws_manager and ws_port and current_ips:
                state._ws_manager.notify_address_changed(current_ips[0], port, ws_port)

        self._schedule_network_monitor()

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
        self._refresh_settings_tunnel_section_if_open()

        self._tunnel = PublicTunnel(port=port + PUBLIC_HTTP_PORT_OFFSET)
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
        if not getattr(self, "_cf_tunnel_active", False):
            state.TUNNEL_ACTIVE = False
        self._draw_public_ready()
        self._log("TUNNEL stopped", "dim")
        self._refresh_settings_tunnel_section_if_open()


    def _on_tunnel_url(self, url: str):
        self._tunnel_url = url
        self.after(0, lambda: self._draw_public_active(url))
        self.after(0, lambda: self._log(f"TUNNEL live -> {url}", "ok"))
        self.after(0, self._refresh_settings_tunnel_section_if_open)


    def _on_tunnel_error(self, msg: str):
        self._tunnel_active = False
        self.after(0, lambda: self._draw_public_error(msg))
        self.after(0, lambda: self._log(f"TUNNEL error: {msg}", "error"))
        self.after(0, self._refresh_settings_tunnel_section_if_open)


    def _on_tunnel_stopped(self):
        pass   # tunnel auto-reconnects; UI feedback via on_reconnecting


    def _on_tunnel_reconnecting(self, delay: int, attempt: int):
        self.after(0, lambda: self._draw_public_reconnecting(delay, attempt))
        self.after(0, lambda: self._log(
            f"TUNNEL lost - reconnecting in {delay}s (attempt {attempt})", "dim"
        ))
        self.after(0, self._refresh_settings_tunnel_section_if_open)

    # Cloudflare custom-domain tunnel lifecycle

    def _start_cloudflare_tunnel(self, hostname: str):
        if not self._running:
            messagebox.showwarning(t("netshare_title"), t("start_server_first"))
            return
        if getattr(self, "_cf_tunnel_active", False):
            return

        from src.core import cloudflare_tunnel as cf
        if not cf.is_installed():
            messagebox.showwarning(t("netshare_title"), t("cf_not_installed"))
            return

        status = cf.setup_status(hostname)
        if not status["tunnel_created"] or not status["config_written"]:
            messagebox.showwarning(t("netshare_title"), t("cf_status_not_ready"))
            return

        config_path = cf._APP_TUNNEL_DIR / "config.yml"
        try:
            port = int(self._port_var.get())
        except ValueError:
            port = DEFAULT_PORT
        cf.retarget_config(config_path, port + PUBLIC_HTTP_PORT_OFFSET)
        self._cf_tunnel_active = True
        self._cf_tunnel_hostname = hostname
        state.TUNNEL_ACTIVE = True

        self._cf_tunnel = cf.CloudflareTunnel(config_path, hostname)
        self._cf_tunnel.start(
            on_url=self._on_cf_tunnel_url,
            on_error=self._on_cf_tunnel_error,
            on_stop=self._on_cf_tunnel_stopped,
            on_reconnecting=self._on_cf_tunnel_reconnecting,
        )
        self._log(f"CF-TUNNEL starting -> {hostname}", "dim")

    def _stop_cloudflare_tunnel(self):
        if getattr(self, "_cf_tunnel", None):
            self._cf_tunnel.stop()
            self._cf_tunnel = None
        self._cf_tunnel_active = False
        self._cf_tunnel_url = ""
        # Don't clobber the SSH tunnel's flag if that one is still running.
        if not self._tunnel_active:
            state.TUNNEL_ACTIVE = False
        self._log("CF-TUNNEL stopped", "dim")
        self._refresh_settings_tunnel_section_if_open()

    def _on_cf_tunnel_url(self, url: str):
        self._cf_tunnel_url = url
        self.after(0, lambda: self._log(f"CF-TUNNEL live -> {url}", "ok"))
        self.after(0, self._refresh_settings_tunnel_section_if_open)

    def _on_cf_tunnel_error(self, msg: str):
        self._cf_tunnel_active = False
        self.after(0, lambda: self._log(f"CF-TUNNEL error: {msg}", "error"))
        self.after(0, self._refresh_settings_tunnel_section_if_open)

    def _on_cf_tunnel_stopped(self):
        pass  # mirrors _on_tunnel_stopped: auto-reconnect handles its own UI via on_reconnecting

    def _on_cf_tunnel_reconnecting(self, delay: int, attempt: int):
        self.after(0, lambda: self._log(
            f"CF-TUNNEL lost - reconnecting in {delay}s (attempt {attempt})", "dim"
        ))
        self.after(0, self._refresh_settings_tunnel_section_if_open)

    def _refresh_settings_tunnel_section_if_open(self):
        """Live-redraw the Settings > Tunnel section if it's the one currently
        open, so tunnel status updates without the host having to reopen the
        modal. No-op if Settings isn't open or a different section is active."""
        refresh = getattr(self, "_settings_refresh_active_section", None)
        if refresh:
            try:
                refresh()
            except Exception:
                pass

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

