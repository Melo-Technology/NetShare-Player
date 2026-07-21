"""PairingPanelMixin extracted from the main GUI window."""

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


class PairingPanelMixin:

    def _draw_write_pairing_placeholder(self):
        frame = getattr(self, "_write_pairing_frame", None)
        if frame is None or not frame.winfo_exists():
            return  # write-pairing now lives in Settings > Permissions; no-op on the main page
        for w in frame.winfo_children():
            w.destroy()
        self._responsive_wrap(tk.Label(
            self._write_pairing_frame,
            text=t("write_pairing_placeholder"),
            font=(FONT_MONO, self._fs(9)),
            fg=FG3(), bg=BG(),
        ), padding=72).pack(anchor="w", fill="x")


    def _draw_write_pairing_active(self, otp: str = ""):
        """Redraw the write-pairing section with a live countdown ring."""
        frame = getattr(self, "_write_pairing_frame", None)
        if frame is None or not frame.winfo_exists():
            return  # write-pairing now lives in Settings > Permissions; no-op on the main page
        for w in frame.winfo_children():
            w.destroy()

        # cancel any running tick so we don't stack timers on refresh
        if hasattr(self, "_otp_after_id") and self._otp_after_id:
            self.after_cancel(self._otp_after_id)
            self._otp_after_id = None

        if not self._running or self._tunnel_active:
            self._draw_write_pairing_placeholder()
            return

        outer = tk.Frame(
            self._write_pairing_frame,
            bg=SURFACE(),
            highlightthickness=1,
            highlightbackground=BORDER(),
        )
        outer.pack(fill="x")
        row = tk.Frame(outer, bg=SURFACE())
        row.pack(fill="x", padx=self._s(12), pady=self._s(10))
        tk.Label(
            row,
            text=t("authenticator_setup"),
            font=(FONT_MONO, self._fs(10), "bold"),
            fg=FG(), bg=SURFACE(),
        ).pack(side="left")
        tk.Label(
            row,
            text=state.TOTP_SECRET,
            font=(FONT_MONO, self._fs(8)),
            fg=FG3(), bg=SURFACE(),
        ).pack(side="left", padx=(self._s(10), 0))
        uri = state.pyotp.TOTP(state.TOTP_SECRET).provisioning_uri(
            name=state.SERVER_NAME,
            issuer_name="NetShare Server",
        )
        if HAS_QRCODE:
            self._write_pairing_button(row, "QR", lambda: self._show_qr(uri))
        self._write_pairing_button(row, t("copy"), lambda: self._copy(state.TOTP_SECRET))

        list_frame = tk.Frame(outer, bg=SURFACE())
        list_frame.pack(fill="x", padx=self._s(12), pady=(0, self._s(10)))
        tk.Label(
            list_frame,
            text=t("trusted_devices"),
            font=(FONT_MONO, self._fs(8)),
            fg=FG3(), bg=SURFACE(),
        ).pack(anchor="w", pady=(0, self._s(4)))
        if not state.TRUSTED_DEVICES:
            tk.Label(
                list_frame,
                text=t("no_devices_paired"),
                font=(FONT_MONO, self._fs(8)),
                fg=FG3(), bg=SURFACE(),
            ).pack(anchor="w")
        else:
            from datetime import datetime
            for device_id, registered_at in sorted(state.TRUSTED_DEVICES.items()):
                dev_row = tk.Frame(list_frame, bg=SURFACE())
                dev_row.pack(fill="x", pady=(0, self._s(3)))
                date = datetime.fromtimestamp(float(registered_at)).strftime("%Y-%m-%d %H:%M")
                tk.Label(
                    dev_row,
                    text=f"{device_id}  {date}",
                    font=(FONT_MONO, self._fs(7)),
                    fg=FG2(), bg=SURFACE(), anchor="w",
                ).pack(side="left", fill="x", expand=True)
                tk.Button(
                    dev_row,
                    text=t("revoke"),
                    font=(FONT_MONO, self._fs(7)),
                    fg=DANGER(), bg=SURFACE(),
                    activeforeground=FG(), activebackground=SURFACE(),
                    relief="flat", bd=0, cursor="hand2",
                    command=lambda d=device_id: self._revoke_trusted_device(d),
                ).pack(side="right")
        return

        outer = tk.Frame(
            self._write_pairing_frame,
            bg=SURFACE(),
            highlightthickness=1,
            highlightbackground=BORDER(),
        )
        outer.pack(fill="x")

        row = tk.Frame(outer, bg=SURFACE())
        row.pack(fill="x", padx=self._s(12), pady=self._s(10))

        if not otp:
            tk.Label(
                row,
                text=t("no_active_otp"),
                font=(FONT_MONO, self._fs(10), "bold"),
                fg=FG3(), bg=SURFACE(),
            ).pack(side="left")
            self._write_pairing_button(row, t("new_otp"), self._refresh_write_otp)
            return

        # Countdown ring canvas
        ring_size = self._s(80)
        cv = tk.Canvas(
            row,
            width=ring_size, height=ring_size,
            bg=SURFACE(), highlightthickness=0,
        )
        cv.pack(side="left", padx=(0, self._s(12)))

        self._otp_ring_canvas  = cv
        self._otp_ring_size    = ring_size

        # OTP code label, updated in place when the ticker regenerates it
        self._otp_code_lbl = tk.Label(
            row,
            text=otp,
            font=(FONT_MONO, self._fs(18), "bold"),
            fg=FG(), bg=SURFACE(),
            cursor="hand2",
        )
        self._otp_code_lbl.pack(side="left")
        self._otp_code_lbl.bind("<Button-1>", lambda e: self._copy(self._write_otp))

        # validity hint (updated by tick)
        ttl_min = state.WRITE_OTP_TTL_SECONDS // 60
        self._otp_validity_lbl = tk.Label(
            row,
            text=t("otp_valid_minutes", minutes=ttl_min),
            font=(FONT_MONO, self._fs(8)),
            fg=FG3(), bg=SURFACE(),
        )
        self._otp_validity_lbl.pack(side="left", padx=(self._s(10), 0))

        self._write_pairing_button(row, t("new_otp"), self._refresh_write_otp)
        tk.Button(
            row,
            text=t("copy"),
            font=(FONT_MONO, self._fs(8)),
            fg=FG3(), bg=SURFACE(),
            activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(8),
            command=lambda: self._copy(self._write_otp),
        ).pack(side="right")

        # start the live ticker
        self._otp_after_id = None
        self._tick_otp_ring()


    def _revoke_trusted_device(self, device_id: str):
        state.revoke_device(device_id)
        self._draw_write_pairing_active()
        self._log(f"PAIR   revoked {device_id}", "dim")


    def _write_pairing_button(self, parent, text: str, command):
        tk.Button(
            parent,
            text=text,
            font=(FONT_MONO, self._fs(8)),
            fg=FG3(), bg=SURFACE(),
            activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(8),
            command=command,
        ).pack(side="right", padx=(self._s(6), 0))


    def _build_otp_ring(self, cv: tk.Canvas, size: int, frac: float, secs_left: int):
        """
        Redraw the countdown ring on *cv*.

        frac      - 0.0 means expired; 1.0 means full
        secs_left - raw seconds remaining for the center label
        """
        cv.delete("all")
        pad = size * 0.1
        x0, y0 = pad, pad
        x1, y1 = size - pad, size - pad
        thickness = max(2, int(size * 0.12))

        # dim background track
        cv.create_oval(x0, y0, x1, y1, outline=BORDER(), width=thickness, fill="")

        # arc color by urgency
        if frac > 0.50:
            color = "#22cc44"
        elif frac > 0.20:
            color = "#f0a500"
        else:
            color = DANGER()

        # arc shrinks clockwise from 12-o'clock
        if frac > 0.005:
            cv.create_arc(x0, y0, x1, y1,
                          start=90, extent=-360.0 * frac,
                          outline=color, width=thickness, style="arc")

        # centre mm:ss label
        cx, cy = size / 2, size / 2
        if secs_left > 0:
            label = f"{secs_left // 60}:{secs_left % 60:02d}"
        else:
            label  = t("new_otp_short")      # briefly shown before auto-regen fires
            color = "#22cc44"  # flash green to signal refresh

        cv.create_text(cx, cy, text=label,
                       font=(FONT_MONO, self._fs(7)),
                       fill=color, anchor="center")


    def _tick_otp_ring(self):
        """1-second heartbeat. Auto-regenerates the OTP when it expires."""
        if not self._running or not state.FEATURE_FLAGS.get("write_pairing"):
            return
        try:
            canvas = self._otp_ring_canvas
            if not canvas.winfo_exists():
                return
        except (AttributeError, tk.TclError):
            return

        now        = time.time()
        expires_at = state.WRITE_OTP_EXPIRES_AT
        ttl_total  = state.WRITE_OTP_TTL_SECONDS
        secs_left  = max(0, int(expires_at - now))
        frac       = secs_left / ttl_total if ttl_total > 0 else 0.0

        if secs_left == 0:
            # Auto-regenerate expired OTP codes
            new_otp        = state.reset_write_auth()
            self._write_otp = new_otp
            self._log(
                f"WRITE  auto-regen OTP {new_otp}"
                f" (valid {ttl_total // 60} min)",
                "ok",
            )
            # flash "new" for one frame then do a full redraw with the fresh code
            self._build_otp_ring(canvas, self._otp_ring_size, 0.0, 0)
            self.after(400, lambda: self._draw_write_pairing_active(new_otp))
            return

        self._build_otp_ring(canvas, self._otp_ring_size, frac, secs_left)

        # update validity text
        try:
            lbl = self._otp_validity_lbl
            if lbl.winfo_exists():
                mins_left = math.ceil(secs_left / 60)
                lbl.configure(
                    text=t("otp_valid_minutes", minutes=mins_left),
                    fg=FG3() if frac > 0.20 else DANGER(),
                )
        except (AttributeError, tk.TclError):
            pass

        # update the code label in case regen just happened (belt-and-suspenders)
        try:
            clbl = self._otp_code_lbl
            if clbl.winfo_exists() and clbl.cget("text") != self._write_otp:
                clbl.configure(text=self._write_otp)
        except (AttributeError, tk.TclError):
            pass

        self._otp_after_id = self.after(1000, self._tick_otp_ring)


    def _refresh_write_otp(self):
        """Manual OTP refresh button."""
        if not self._running or not state.FEATURE_FLAGS.get("write_pairing"):
            return
        self._write_otp = state.reset_write_auth()
        self._draw_write_pairing_active(self._write_otp)
        self._log(
            f"WRITE  OTP {self._write_otp}"
            f" (valid {state.WRITE_OTP_TTL_SECONDS // 60} min)",
            "ok",
        )

