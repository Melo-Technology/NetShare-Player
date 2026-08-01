"""ActionsMixin extracted from the main GUI window."""

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


class ActionsMixin:

    # Sleep inhibitor toggle

    def _toggle_sleep_inhibit(self):
        self._sleep_inhibit_enabled = not self._sleep_inhibit_enabled
        inhibit_sleep(self._sleep_inhibit_enabled)
        sleep_btn = getattr(self, "_sleep_btn", None)
        if sleep_btn is None or not sleep_btn.winfo_exists():
            return  # main-page button removed; Settings > Permissions reflects state on its own render
        if self._sleep_inhibit_enabled:
            sleep_btn.config(
                text=f"☀  {t('keep_awake_on')}",
                fg=FG(), bg=SURFACE2(),
                highlightbackground=FG(),
            )
        else:
            sleep_btn.config(
                text=f"☾  {t('keep_awake')}",
                fg=FG3(), bg=BG(),
                highlightbackground=BORDER(),
            )


    def _show_sleep_btn(self):
        sleep_btn_outer = getattr(self, "_sleep_btn_outer", None)
        if sleep_btn_outer is None or not sleep_btn_outer.winfo_exists():
            return
        sleep_btn_outer.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0),
                                   after=self._toggle_btn.master)


    def _hide_sleep_btn(self):
        sleep_btn_outer = getattr(self, "_sleep_btn_outer", None)
        if sleep_btn_outer is not None and sleep_btn_outer.winfo_exists():
            sleep_btn_outer.pack_forget()
        if self._sleep_inhibit_enabled:
            self._sleep_inhibit_enabled = False
            inhibit_sleep(False)
            sleep_btn = getattr(self, "_sleep_btn", None)
            if sleep_btn is not None and sleep_btn.winfo_exists():
                sleep_btn.config(
                    text=f"☾  {t('keep_awake')}",
                    fg=FG3(), bg=BG(),
                    highlightbackground=BORDER(),
                )

    # Folder actions


    # Folder actions

    def _browse_folder(self):
        folder = filedialog.askdirectory(title=t("select_folder_title"))
        if folder:
            self._select_folder(folder)


    def _select_folder(self, folder: str):
        self._selected_folder.set(folder)
        name = Path(folder).name or folder
        self._folder_display.configure(text=name, fg=FG(), highlightbackground=FG())
        if folder not in self._folder_history:
            self._folder_history.append(folder)
        self._refresh_history()
        if self._running:
            state.ROOT_DIR = Path(folder).resolve()
            _file_index.flush_if_dirty(state.ROOT_DIR)
            _file_index.clear()
            _file_index.build(state.ROOT_DIR)
            _start_watcher(state.ROOT_DIR)
            _file_index.start_periodic_flush(state.ROOT_DIR)
            if state._ws_manager:
                state._ws_manager.notify_file_change("/")
            self._log(f"ROOT   changed -> {state.ROOT_DIR}", "info")

    def _save_local_password(self):
        try:
            days = int(self._password_reminder_days_var.get())
            state.save_password_reminder_days(days)
        except (ValueError, tk.TclError):
            messagebox.showerror(t("invalid_duration_title"), t("invalid_duration_message"))
            return
        state.save_local_password(self._password_var.get())
        self._password_var.set(state.LOCAL_PASSWORD)
        messagebox.showinfo(
            t("password_saved_title"),
            t("password_saved_message", days=state.PASSWORD_REMINDER_DAYS),
        )

    # Server lifecycle

