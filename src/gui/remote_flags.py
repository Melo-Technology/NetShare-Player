"""RemoteFlagsMixin extracted from the main GUI window."""

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


class RemoteFlagsMixin:

    def _change_language(self, code: str):
        set_language(code)
        self._language_var.set(code)
        yview = self._canvas.yview()[0] if hasattr(self, "_canvas") else 0

        for child in self._body.winfo_children():
            child.destroy()

        self._build_header()
        self._section_label(t("directory")); self._build_folder_section()
        self._build_server_button()
        self._build_addresses_section()
        self._build_incoming_section()
        self._build_log_section()
        self._build_footer()

        folder = self._selected_folder.get()
        if folder:
            name = Path(folder).name or folder
            self._folder_display.configure(text=name, fg=FG(), highlightbackground=FG())

        if self._running:
            self._toggle_btn.configure(text=t("stop_server"), bg=DANGER(), fg=FG())
            self._add_hover(self._toggle_btn, DANGER(), "#991111",
                            text_normal=FG(), text_hover=FG())
            self._set_write_options_enabled(False)
            self._status_canvas.itemconfig(self._status_dot_id, fill="#22cc44")
            self._status_lbl.configure(text=t("online"), fg=FG())
            try:
                port = int(self._port_var.get())
            except ValueError:
                port = DEFAULT_PORT
            ws_port = port + 1 if HAS_WEBSOCKETS else None
            self._update_addr_block(port, ws_port)
            # Write-pairing / keep-awake button / public-sharing panel used to
            # be redrawn here too, back when they lived on the main page.
            # They're Settings-modal content now (Permissions / Tunnel /
            # Sharing); those sections pull current state fresh every time
            # they're opened, so there's nothing to push into them here.

        self.after(0, lambda: self._canvas.yview_moveto(yview))
        self._apply_remote_flags_to_ui()  # re-apply after rebuilding UI

    # Address block


    # Address block

    def _update_addr_block(self, port: int, ws_port):
        for w in self._addr_frame.winfo_children():
            w.destroy()
        ips = get_local_ips()
        for i, ip in enumerate(ips):
            url = f"http://{ip}:{port}"
            row = tk.Frame(self._addr_frame, bg=BG())
            row.pack(fill="x", pady=(0, self._s(6)))
            tk.Label(row, text=f"{i+1:02d}", font=(FONT_MONO, self._fs(8)),
                     fg=FG3(), bg=BG(), width=3, anchor="w").pack(side="left")
            url_lbl = tk.Label(row, text=url, font=(FONT_MONO, self._fs(10), "bold"),
                               fg=FG(), bg=BG(), cursor="hand2")
            url_lbl.pack(side="left")
            url_lbl.bind("<Button-1>", lambda e, u=url: self._copy(u))
            if ws_port:
                tk.Label(row, text=f"WS :{ws_port}", font=(FONT_MONO, self._fs(8)),
                         fg=FG3(), bg=BG()).pack(side="left", padx=(self._s(10), 0))
            if HAS_QRCODE:
                tk.Button(row, text="QR", font=(FONT_MONO, self._fs(8)),
                          fg=FG3(), bg=BG(), activeforeground=FG(), activebackground=BG(),
                          relief="flat", bd=0, cursor="hand2", padx=self._s(8),
                          command=lambda u=url: self._show_qr(u)
                          ).pack(side="right")
            tk.Button(row, text=t("copy"), font=(FONT_MONO, self._fs(8)),
                      fg=FG3(), bg=BG(), activeforeground=FG(), activebackground=BG(),
                      relief="flat", bd=0, cursor="hand2", padx=self._s(8),
                      command=lambda u=url: self._copy(u)
                      ).pack(side="right")
            if i < len(ips) - 1:
                tk.Frame(self._addr_frame, bg=BORDER(), height=1).pack(
                    fill="x", pady=(0, self._s(6))
                )

    # Remote feature-flag sync


    # Remote feature-flag sync

    def _fetch_remote_flags_async(self):
        """Fetch Remote Config flags in a background thread; apply on the main thread."""
        if not HAS_FIREBASE:
            return

        def _worker():
            try:
                from src.core.firebase import fetch_feature_flags
                flags = fetch_feature_flags()
                if flags:
                    self.after(0, lambda: self._apply_remote_flags(flags))
                else:
                    self.after(0, self._set_firebase_label_error)
            except Exception:
                self.after(0, self._set_firebase_label_error)

        threading.Thread(target=_worker, daemon=True).start()


    def _apply_remote_flags(self, flags: dict):
        """
        Called on the main thread after a successful Remote Config fetch.

        Updates the cached flag state, hides/shows the permission checkboxes,
        and logs the result so the operator can see what was applied.
        """
        upload_enabled = bool(flags.get("upload", True))
        edit_enabled   = bool(flags.get("document_edit", True))

        self._remote_flags["upload"]        = upload_enabled
        self._remote_flags["document_edit"] = edit_enabled

        self._apply_remote_flags_to_ui()
        if getattr(self, "_tunnel_active", False) and getattr(self, "_tunnel_url", ""):
            self._draw_public_active(self._tunnel_url)

        # Keep the legacy status hooks no-op when the header indicator is hidden
        self._set_firebase_label_ok()

        self._log(
            f"FLAGS  upload={'on' if upload_enabled else 'OFF (remotely disabled)'}  "
            f"edit={'on' if edit_enabled else 'OFF (remotely disabled)'}",
            "ok" if (upload_enabled and edit_enabled) else "dim",
        )


    def _apply_remote_flags_to_ui(self):
        upload_ok = self._remote_flags.get("upload")
        edit_ok   = self._remote_flags.get("document_edit")

        upload_visible = (upload_ok is None) or upload_ok
        edit_visible   = (edit_ok   is None) or edit_ok
        def _widget_exists(widget):
            try:
                return bool(widget.winfo_exists())
            except tk.TclError:
                return False

        # Checkboxes
        try:
            cb_upload = self._upload_cb
            cb_edit   = self._edit_cb
            if not (_widget_exists(cb_upload) and _widget_exists(cb_edit)):
                return
            if upload_visible:
                cb_upload.pack(fill="x", anchor="w")
            else:
                cb_upload.pack_forget()
                self._allow_upload_var.set(False)
            if edit_visible:
                cb_edit.pack(fill="x", anchor="w")
            else:
                cb_edit.pack_forget()
                self._allow_edit_var.set(False)
        except (AttributeError, tk.TclError):
            pass

        # Write-pairing, public sharing, and incoming sections.
        # Visible only when at least one write feature is enabled remotely.
        # If flags have not been fetched yet, keep the default visible state.
        write_sections_visible = upload_visible or edit_visible

        for attr in ("_write_pairing_outer", "_public_outer", "_incoming_outer"):
            try:
                widget = getattr(self, attr)
                if not _widget_exists(widget):
                    continue
                if write_sections_visible:
                    widget.pack(fill="x")
                else:
                    widget.pack_forget()
            except (AttributeError, tk.TclError):
                pass  # Not built yet; ignore.


    def _set_firebase_label_ok(self):
        """Turn the Firebase header indicator green after a successful fetch."""
        if self._firebase_lbl:
            try:
                self._firebase_lbl.configure(text=t("feature_flags_ok"), fg="#22cc44")
            except tk.TclError:
                pass


    def _set_firebase_label_error(self):
        """Turn the Firebase header indicator red on fetch failure."""
        if self._firebase_lbl:
            try:
                self._firebase_lbl.configure(text=t("feature_flags_error"), fg=DANGER())
            except tk.TclError:
                pass

    # Placeholder / state draw helpers


    # Placeholder / state draw helpers

    def _draw_offline_placeholder(self):
        for w in self._addr_frame.winfo_children():
            w.destroy()
        self._responsive_wrap(tk.Label(self._addr_frame, text=t("addresses_placeholder"),
                 font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=BG()), padding=72).pack(anchor="w", fill="x")

