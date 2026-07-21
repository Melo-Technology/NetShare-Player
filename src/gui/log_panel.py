"""LogPanelMixin extracted from the main GUI window."""

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


class LogPanelMixin:

    # Log helpers

    def _log(self, msg: str, kind: str = "info"):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        # Keep following live logs only while the user is already at the end.
        # Scrolling upward pauses auto-follow so older entries remain readable.
        was_at_bottom = self._log_text.yview()[1] >= 0.999
        self._log_text.configure(state="normal")
        self._log_text.insert("end", f"[{ts}]  ", "ts")
        self._log_text.insert("end", f"{msg}\n", kind)
        if was_at_bottom:
            self._log_text.see("end")
        self._log_text.configure(state="disabled")


    def _export_logs(self):
        content = self._log_text.get("1.0", "end-1c").strip()
        if not content:
            messagebox.showinfo(t("log"), t("no_logs_to_export"), parent=self)
            return
        from datetime import datetime
        filename = f"netshare-logs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        target = filedialog.asksaveasfilename(
            parent=self,
            title=t("export_logs"),
            initialfile=filename,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not target:
            return
        try:
            header = (
                f"NetShare Player Server {VERSION}\n"
                f"Exported: {datetime.now().isoformat(timespec='seconds')}\n"
                f"{'=' * 72}\n"
            )
            Path(target).write_text(header + content + "\n", encoding="utf-8")
            self._log(f"{t('logs_exported')}  {target}", "ok")
        except OSError as exc:
            messagebox.showerror(t("log"), str(exc), parent=self)


    def _add_incoming_line(self, msg: str, kind: str = "info"):
        if not hasattr(self, "_incoming_text"):
            return
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self._incoming_text.configure(state="normal")
        self._incoming_text.insert("end", f"[{ts}]  ", "dim")
        self._incoming_text.insert("end", f"{msg}\n", kind)
        self._incoming_text.see("end")
        self._incoming_text.configure(state="disabled")


    def _clear_incoming(self):
        if not hasattr(self, "_incoming_text"):
            return
        self._incoming_text.configure(state="normal")
        self._incoming_text.delete("1.0", "end")
        self._incoming_text.configure(state="disabled")


    def _format_size(self, size):
        if size is None:
            return ""
        try:
            size = int(size)
        except (TypeError, ValueError):
            return ""
        units = ("B", "KB", "MB", "GB")
        value = float(size)
        unit = units[0]
        for unit in units:
            if value < 1024 or unit == units[-1]:
                break
            value /= 1024
        if unit == "B":
            return f"{int(value)} {unit}"
        return f"{value:.1f} {unit}"


    def _render_write_activity(self, event: dict):
        action = event.get("action", "write")
        if action == "upload-request":
            self._render_upload_request(event)
            return
        path = event.get("path", "")
        client = event.get("client", "")
        size = self._format_size(event.get("size"))
        suffix = f"  {size}" if size else ""
        prefix = f"{client}  " if client else ""
        if action == "receiving":
            self._add_incoming_line(f"{prefix}{t('receiving')} {path}{suffix}", "info")
        elif action == "received":
            self._add_incoming_line(f"{prefix}{t('received')}  {path}{suffix}", "ok")
        elif action == "edited":
            self._add_incoming_line(f"{prefix}{t('edited')}    {path}{suffix}", "ok")
        elif action == "rate-limit":
            self._add_incoming_line(f"{prefix}{t('rate_limit_hit')}", "error")
        else:
            self._add_incoming_line(f"{prefix}{action} {path}{suffix}", "info")


    def _render_upload_request(self, event: dict):
        if not hasattr(self, "_pending_uploads_frame"):
            return
        request_id = event.get("request_id", "")
        filename = event.get("path", "")
        client = event.get("client", "")
        size = self._format_size(event.get("size"))

        card = tk.Frame(
            self._pending_uploads_frame,
            bg=SURFACE(),
            highlightthickness=1,
            highlightbackground=BORDER(),
        )
        card.pack(fill="x", pady=(0, self._s(6)))

        title = tk.Label(
            card,
            text=t("upload_request_title", client=client, filename=filename),
            font=(FONT_MONO, self._fs(8), "bold"),
            fg=FG(), bg=SURFACE(),
            anchor="w",
        )
        self._responsive_wrap(title, padding=96)
        title.pack(fill="x", padx=self._s(10), pady=(self._s(8), 0))

        status = tk.Label(
            card,
            text=t("upload_pending", size=size),
            font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=SURFACE(),
            anchor="w",
        )
        self._responsive_wrap(status, padding=96)
        status.pack(fill="x", padx=self._s(10), pady=(self._s(2), self._s(6)))

        buttons = tk.Frame(card, bg=SURFACE())
        buttons.pack(fill="x", padx=self._s(10), pady=(0, self._s(8)))

        def _decide(accepted: bool):
            result = state.resolve_public_upload_request(request_id, accepted)
            if not result:
                status.config(text=t("request_expired"), fg=DANGER())
            elif accepted:
                status.config(text=t("accepted_waiting_upload"), fg=FG())
                self._add_incoming_line(f"{t('accepted')}  {filename}", "ok")
            else:
                status.config(text=t("declined"), fg=DANGER())
                self._add_incoming_line(f"{t('declined')}  {filename}", "error")
            buttons.destroy()

        tk.Button(
            buttons,
            text=t("accept"),
            font=(FONT_MONO, self._fs(7), "bold"),
            fg=BG(), bg=FG(),
            activeforeground=BG(), activebackground=FG2(),
            relief="flat", bd=0, cursor="hand2",
            command=lambda: _decide(True),
        ).pack(side="left", padx=(0, self._s(6)))
        tk.Button(
            buttons,
            text=t("decline"),
            font=(FONT_MONO, self._fs(7), "bold"),
            fg=FG(), bg=DANGER(),
            activeforeground=FG(), activebackground=DANGER(),
            relief="flat", bd=0, cursor="hand2",
            command=lambda: _decide(False),
        ).pack(side="left")


    def _copy(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._log(f"{t('copied')}  {text}", "dim")

    # Log drainer


    # Log drainer

    def _start_log_drainer(self):
        self._drainer_active = True
        self._drain_log_queue()


    def _stop_log_drainer(self):
        self._drainer_active = False


    def _drain_log_queue(self):
        try:
            while True:
                msg, kind = state._log_queue.get_nowait()
                self._log(msg, kind)
        except queue.Empty:
            pass
        try:
            while True:
                event = state._write_activity_queue.get_nowait()
                self._render_write_activity(event)
        except queue.Empty:
            pass
        if getattr(self, "_drainer_active", False):
            self.after(50, self._drain_log_queue)

    # Sleep inhibitor toggle

