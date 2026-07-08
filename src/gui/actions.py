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
        if self._sleep_inhibit_enabled:
            self._sleep_btn.config(
                text=f"☀  {t('keep_awake_on')}",
                fg=FG(), bg=SURFACE2(),
                highlightbackground=FG(),
            )
        else:
            self._sleep_btn.config(
                text=f"☾  {t('keep_awake')}",
                fg=FG3(), bg=BG(),
                highlightbackground=BORDER(),
            )


    def _show_sleep_btn(self):
        self._sleep_btn_outer.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0),
                                   after=self._toggle_btn.master)


    def _hide_sleep_btn(self):
        self._sleep_btn_outer.pack_forget()
        if self._sleep_inhibit_enabled:
            self._sleep_inhibit_enabled = False
            inhibit_sleep(False)
            self._sleep_btn.config(
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

    # Server lifecycle

