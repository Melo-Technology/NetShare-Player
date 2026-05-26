"""
NetShare Player — Main GUI application window (App)

App is the root tk.Tk window. It owns:
  • the scrollable main canvas + all sub-sections (header, config, log …)
  • server lifecycle (_start_server / _stop_server)
  • tunnel lifecycle (_start_tunnel / _stop_tunnel)
  • the log-drainer Tkinter timer
  • sleep-inhibitor toggle
"""

import queue
import socket
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import tkinter as tk

import src.state as state
from src.constants import VERSION, DEFAULT_PORT, MAX_HISTORY, FONT_MONO
from src.deps import HAS_WEBSOCKETS, HAS_QRCODE
from src.i18n import DEFAULT_LANGUAGE, LANGUAGES, set_language, t
from src.theme import _theme, _DARK, BG, SURFACE, SURFACE2, BORDER, FG, FG2, FG3, DANGER
from src.utils.platform import PLATFORM
from src.utils.network import get_local_ips
from src.utils.sleep import inhibit_sleep
from src.core.file_index import _file_index, _start_watcher, _stop_watcher
from src.core.ws_manager import WebSocketManager, _run_ws_server
from src.core.tunnel import PublicTunnel
from src.gui.theme_mixin import ThemeMixin
from src.gui.dialogs import ask_tunnel_password
from src.routes.handler import NetShareHandler
from http.server import ThreadingHTTPServer


class App(ThemeMixin, tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("NETSHARE PLAYER")

        # == Theme ==============================================================
        self._dark_mode = True
        _theme.update(_DARK)

        # == DPI / scale ========================================================
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

        # == Server state =======================================================
        self._server    = None
        self._thread    = None
        self._running   = False
        self._ws_thread = None

        # == Sleep inhibitor ====================================================
        self._sleep_inhibit_enabled = False

        # == Tunnel state =======================================================
        self._tunnel:         PublicTunnel | None = None
        self._tunnel_active   = False
        self._tunnel_url      = ""
        self._tunnel_pw       = ""
        self._public_btn      = None
        self._public_section  = None

        # == Tkinter variables ==================================================
        self._selected_folder  = tk.StringVar(value="")
        self._port_var         = tk.StringVar(value=str(DEFAULT_PORT))
        self._name_var         = tk.StringVar(value=socket.gethostname())
        self._password_var     = tk.StringVar(value="")
        self._language_var     = tk.StringVar(value=DEFAULT_LANGUAGE)
        self._folder_history: list[str] = []

        # == Icon ===============================================================
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

    # == Scale helpers ==========================================================

    def _s(self, v: int) -> int:
        return int(v * self._ui_scale)

    def _fs(self, v: int) -> int:
        return v if PLATFORM == "mac" else max(1, int(v * self._ui_scale))

    # == UI construction ========================================================

    def _build_ui(self):
        outer = tk.Frame(self, bg=BG())
        outer.pack(fill="both", expand=True)

        self._canvas    = tk.Canvas(outer, bg=BG(), highlightthickness=0, bd=0)
        self._scrollbar = tk.Scrollbar(
            outer, orient="vertical", command=self._canvas.yview,
            bg=BG(), troughcolor=SURFACE(), activebackground=FG3(),
        )
        self._canvas.configure(yscrollcommand=self._scrollbar.set)
        self._scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._body       = tk.Frame(self._canvas, bg=BG())
        self._body_win_id = self._canvas.create_window((0, 0), window=self._body, anchor="nw")

        def _on_canvas_resize(e):
            self._canvas.itemconfig(self._body_win_id, width=e.width)
        self._canvas.bind("<Configure>", _on_canvas_resize)

        def _on_body_resize(e):
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
            bb = self._canvas.bbox("all")
            if bb:
                if bb[3] <= self._canvas.winfo_height():
                    self._scrollbar.pack_forget()
                else:
                    self._scrollbar.pack(side="right", fill="y")
        self._body.bind("<Configure>", _on_body_resize)

        def _on_mousewheel(e):
            if e.num == 4:
                self._canvas.yview_scroll(-1, "units")
            elif e.num == 5:
                self._canvas.yview_scroll(1, "units")
            else:
                units = int(-1 * (e.delta / 120)) if PLATFORM == "windows" else int(-1 * e.delta)
                self._canvas.yview_scroll(units, "units")
        self._canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self._canvas.bind_all("<Button-4>",   _on_mousewheel)
        self._canvas.bind_all("<Button-5>",   _on_mousewheel)

        self._build_header()
        self._section_label(t("directory")); self._build_folder_section()
        self._section_label(t("config"));    self._build_config_section()
        self._build_server_button()
        self._build_sleep_button()
        self._build_addresses_section()
        self._build_public_section()
        self._build_log_section()
        self._build_footer()

    # == Header =================================================================

    def _build_header(self):
        header = tk.Frame(self._body, bg=BG())
        header.pack(fill="x", padx=self._s(24), pady=(self._s(28), 0))

        logo_size = self._s(32)
        logo_cv   = tk.Canvas(header, width=logo_size, height=logo_size,
                              bg=BG(), highlightthickness=0)
        logo_cv.pack(side="left", padx=(0, self._s(12)))
        logo_cv.create_rectangle(0, 0, logo_size, logo_size, fill=FG(), outline="")
        lw = max(2, self._s(3)); m = self._s(8); e = logo_size - m
        logo_cv.create_line(m, e, m, m, fill=BG(), width=lw, capstyle="projecting")
        logo_cv.create_line(m, m, e, e, fill=BG(), width=lw, capstyle="projecting")
        logo_cv.create_line(e, e, e, m, fill=BG(), width=lw, capstyle="projecting")

        title_frame = tk.Frame(header, bg=BG())
        title_frame.pack(side="left")
        tk.Label(title_frame, text="N E T S H A R E",
                 font=(FONT_MONO, self._fs(14), "bold"),
                 fg=FG(), bg=BG()).pack(side="left")
        tk.Label(title_frame, text="  P L A Y E R",
                 font=(FONT_MONO, self._fs(14)),
                 fg=FG2(), bg=BG()).pack(side="left")

        subheader = tk.Frame(self._body, bg=BG())
        subheader.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0))

        self._theme_btn = tk.Button(
            subheader,
            text="☀",
            font=(FONT_MONO, self._fs(11)),
            fg=_theme["TOGGLE_FG"], bg=_theme["TOGGLE_BG"],
            activebackground=_theme["TOGGLE_BG"], activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(4),
            command=self._toggle_theme,
        )
        self._theme_btn.pack(side="left")

        status_frame = tk.Frame(subheader, bg=BG())
        status_frame.pack(side="right")
        dot_size = self._s(8)
        self._status_canvas = tk.Canvas(status_frame, width=dot_size, height=dot_size,
                                        bg=BG(), highlightthickness=0)
        self._status_canvas.pack(side="left", padx=(0, self._s(6)))
        self._status_dot_id = self._status_canvas.create_rectangle(
            0, 0, dot_size, dot_size, fill=FG3(), outline=""
        )
        self._status_lbl = tk.Label(status_frame, text=t("offline"),
                                    font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=BG())
        self._status_lbl.pack(side="left")

        self._hairline()

        ver_frame = tk.Frame(self._body, bg=BG())
        ver_frame.pack(fill="x", padx=self._s(24), pady=(self._s(10), 0))
        tk.Label(ver_frame, text=f"V{VERSION}",
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=BG()).pack(side="left")
        tk.Label(ver_frame, text="MÉLO TECHNOLOGY",
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=BG()).pack(side="right")

        lang_frame = tk.Frame(self._body, bg=BG())
        lang_frame.pack(fill="x", padx=self._s(24), pady=(self._s(10), 0))
        tk.Label(lang_frame, text=t("language"),
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=BG()).pack(side="left")
        lang_menu = tk.OptionMenu(
            lang_frame,
            self._language_var,
            *LANGUAGES.keys(),
            command=self._change_language,
        )
        lang_menu.configure(
            font=(FONT_MONO, self._fs(8)),
            fg=FG(), bg=SURFACE(),
            activebackground=SURFACE2(), activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2",
            highlightthickness=1, highlightbackground=BORDER(),
            width=4,
        )
        lang_menu.pack(side="right")
        try:
            lang_menu["menu"].configure(
                font=(FONT_MONO, self._fs(8)),
                fg=FG(), bg=SURFACE(),
                activebackground=SURFACE2(), activeforeground=FG(),
            )
        except Exception:
            pass

    # == Folder section =========================================================

    def _build_folder_section(self):
        outer = tk.Frame(self._body, bg=BG())
        outer.pack(fill="x", padx=self._s(24), pady=(0, self._s(4)))
        self._folder_display = tk.Label(
            outer, text=t("no_folder"),
            font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=SURFACE(),
            anchor="w", padx=self._s(12), pady=self._s(10), width=32,
            highlightthickness=1, highlightbackground=BORDER(),
        )
        self._folder_display.pack(side="left", fill="x", expand=True)
        browse_btn = tk.Button(
            outer, text=t("browse"),
            font=(FONT_MONO, self._fs(9), "bold"),
            fg=FG(), bg=SURFACE2(),
            activebackground=FG(), activeforeground=BG(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(14), pady=self._s(10),
            highlightthickness=1, highlightbackground=BORDER(),
            command=self._browse_folder,
        )
        browse_btn.pack(side="right", padx=(self._s(6), 0))
        self._add_hover(browse_btn, SURFACE2(), FG(), text_normal=FG(), text_hover=BG())

        self._hist_outer = tk.Frame(self._body, bg=BG())
        self._hist_outer.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0))
        self._refresh_history()

    def _refresh_history(self):
        for w in self._hist_outer.winfo_children():
            w.destroy()
        if not self._folder_history:
            return
        tk.Label(self._hist_outer, text=t("recent"),
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=BG()
                 ).pack(side="left", padx=(0, self._s(8)))
        for folder in reversed(self._folder_history[-MAX_HISTORY:]):
            name = Path(folder).name or folder
            btn  = tk.Button(
                self._hist_outer, text=name[:14],
                font=(FONT_MONO, self._fs(8)),
                fg=FG2(), bg=BG(),
                activebackground=SURFACE2(), activeforeground=FG(),
                relief="flat", bd=0, cursor="hand2",
                padx=self._s(8), pady=self._s(3),
                highlightthickness=1, highlightbackground=BORDER(),
                command=lambda f=folder: self._select_folder(f),
            )
            btn.pack(side="left", padx=(0, self._s(4)))

    # == Config section =========================================================

    def _build_config_section(self):
        row = tk.Frame(self._body, bg=BG())
        row.pack(fill="x", padx=self._s(24), pady=(0, self._s(4)))

        tk.Label(row, text=t("port"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left", padx=(0, self._s(6)))
        port_entry = tk.Entry(
            row, textvariable=self._port_var,
            font=(FONT_MONO, self._fs(10)), fg=FG(), bg=SURFACE(),
            insertbackground=FG(), relief="flat", bd=0, width=6,
            highlightthickness=1, highlightbackground=BORDER(),
        )
        port_entry.pack(side="left", ipady=self._s(8), padx=(0, self._s(20)))
        port_entry.bind("<FocusIn>",  lambda e: port_entry.config(highlightbackground=FG()))
        port_entry.bind("<FocusOut>", lambda e: port_entry.config(highlightbackground=BORDER()))

        tk.Label(row, text=t("name"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left", padx=(0, self._s(6)))
        name_entry = tk.Entry(
            row, textvariable=self._name_var,
            font=(FONT_MONO, self._fs(10)), fg=FG(), bg=SURFACE(),
            insertbackground=FG(), relief="flat", bd=0, width=18,
            highlightthickness=1, highlightbackground=BORDER(),
        )
        name_entry.pack(side="left", ipady=self._s(8))
        name_entry.bind("<FocusIn>",  lambda e: name_entry.config(highlightbackground=FG()))
        name_entry.bind("<FocusOut>", lambda e: name_entry.config(highlightbackground=BORDER()))

        # == Local password row =================================================
        pw_row = tk.Frame(self._body, bg=BG())
        pw_row.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0))

        tk.Label(pw_row, text=t("local_pw"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left", padx=(0, self._s(6)))

        self._pw_entry = tk.Entry(
            pw_row, textvariable=self._password_var,
            font=(FONT_MONO, self._fs(10)), fg=FG(), bg=SURFACE(),
            insertbackground=FG(), relief="flat", bd=0, width=16,
            highlightthickness=1, highlightbackground=BORDER(), show="•",
        )
        self._pw_entry.pack(side="left", ipady=self._s(8), padx=(0, self._s(6)))
        self._pw_entry.bind("<FocusIn>",  lambda e: self._pw_entry.config(highlightbackground=FG()))
        self._pw_entry.bind("<FocusOut>", lambda e: self._pw_entry.config(highlightbackground=BORDER()))

        self._pw_show_var = tk.BooleanVar(value=False)

        def _toggle_pw_visibility():
            if self._pw_show_var.get():
                self._pw_entry.config(show="•")
                self._pw_show_var.set(False)
                self._pw_toggle_btn.config(text=t("show"))
            else:
                self._pw_entry.config(show="")
                self._pw_show_var.set(True)
                self._pw_toggle_btn.config(text=t("hide"))

        self._pw_toggle_btn = tk.Button(
            pw_row, text=t("show"),
            font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=BG(),
            activeforeground=FG(), activebackground=BG(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(6),
            command=_toggle_pw_visibility,
        )
        self._pw_toggle_btn.pack(side="left", padx=(0, self._s(6)))
        tk.Label(pw_row, text=t("lan_only"), font=(FONT_MONO, self._fs(7)),
                 fg=FG3(), bg=BG()).pack(side="left")

    # == Server button ==========================================================

    def _build_server_button(self):
        btn_outer = tk.Frame(self._body, bg=BG())
        btn_outer.pack(fill="x", padx=self._s(24), pady=(self._s(16), 0))
        self._toggle_btn = tk.Button(
            btn_outer, text=t("start_server"),
            font=(FONT_MONO, self._fs(11), "bold"),
            fg=BG(), bg=FG(),
            activebackground=FG2(), activeforeground=BG(),
            relief="flat", bd=0, cursor="hand2",
            pady=self._s(14),
            command=self._toggle_server,
        )
        self._toggle_btn.pack(fill="x")
        self._add_hover(self._toggle_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())

    # == Sleep / keep-awake button ==============================================

    def _build_sleep_button(self):
        self._sleep_btn_outer = tk.Frame(self._body, bg=BG())
        self._sleep_btn_outer.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0))
        self._sleep_btn = tk.Button(
            self._sleep_btn_outer,
            text=f"☾  {t('keep_awake')}",
            font=(FONT_MONO, self._fs(9)),
            fg=FG3(), bg=BG(),
            activeforeground=FG(), activebackground=SURFACE2(),
            relief="flat", bd=0, cursor="hand2",
            pady=self._s(8),
            highlightthickness=1,
            highlightbackground=BORDER(),
            command=self._toggle_sleep_inhibit,
        )
        self._sleep_btn.pack(fill="x")
        self._sleep_btn_outer.pack_forget()   # hidden until server starts

    # == Addresses section ======================================================

    def _build_addresses_section(self):
        self._section_label(t("addresses"))
        self._addr_frame = tk.Frame(self._body, bg=BG())
        self._addr_frame.pack(fill="x", padx=self._s(24), pady=(0, self._s(6)))
        self._draw_offline_placeholder()

    # == Public sharing section =================================================

    def _build_public_section(self):
        self._section_label(t("public_sharing"))
        self._public_section = tk.Frame(self._body, bg=BG())
        self._public_section.pack(fill="x", padx=self._s(24), pady=(0, self._s(6)))
        self._draw_public_offline_placeholder()

    # == Log section ============================================================

    def _build_log_section(self):
        self._section_label(t("log"))
        log_outer = tk.Frame(self._body, bg=SURFACE(),
                             highlightthickness=1, highlightbackground=BORDER())
        log_outer.pack(fill="x", padx=self._s(24), pady=(0, self._s(12)))
        self._log_text = tk.Text(
            log_outer, height=9, bg=SURFACE(), fg=FG2(),
            font=(FONT_MONO, self._fs(9)), relief="flat", bd=0,
            padx=self._s(12), pady=self._s(10),
            state="disabled", insertbackground=FG(), wrap="word", cursor="arrow",
        )
        self._log_text.pack(fill="x")
        self._log_text.tag_configure("info",  foreground=FG2())
        self._log_text.tag_configure("ok",    foreground=FG())
        self._log_text.tag_configure("error", foreground=DANGER())
        self._log_text.tag_configure("dim",   foreground=FG3())
        self._log_text.tag_configure("ts",    foreground=FG3())

    # == Footer =================================================================

    def _build_footer(self):
        footer_frame = tk.Frame(self._body, bg=BG(),
                                highlightthickness=1, highlightbackground=BORDER())
        footer_frame.pack(fill="x", padx=self._s(24), pady=(0, self._s(24)))
        tk.Label(
            footer_frame,
            text=f"!  {t('footer_warning')}",
            font=(FONT_MONO, self._fs(8)),
            fg=DANGER(), bg=BG(), pady=self._s(8),
        ).pack()

    # == Shared layout helpers ==================================================

    def _hairline(self, padx=None, pady=None):
        if padx is None: padx = self._s(24)
        if pady is None: pady = (self._s(12), 0)
        tk.Frame(self._body, bg=BORDER(), height=1).pack(fill="x", padx=padx, pady=pady)

    def _section_label(self, text: str):
        frame = tk.Frame(self._body, bg=BG())
        frame.pack(fill="x", padx=self._s(24), pady=(self._s(18), self._s(8)))
        tk.Label(frame, text=text, font=(FONT_MONO, self._fs(8), "bold"),
                 fg=FG3(), bg=BG()).pack(side="left")
        tk.Frame(frame, bg=BORDER(), height=1).pack(
            side="left", fill="x", expand=True,
            padx=(self._s(10), 0), pady=(1, 0),
        )

    def _add_hover(self, widget, normal_bg, hover_bg, text_normal=None, text_hover=None):
        def on_enter(e):
            widget.configure(bg=hover_bg)
            if text_hover:
                widget.configure(fg=text_hover)
        def on_leave(e):
            widget.configure(bg=normal_bg)
            if text_normal:
                widget.configure(fg=text_normal)
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def _change_language(self, code: str):
        set_language(code)
        self._language_var.set(code)
        yview = self._canvas.yview()[0] if hasattr(self, "_canvas") else 0

        for child in self._body.winfo_children():
            child.destroy()

        self._build_header()
        self._section_label(t("directory")); self._build_folder_section()
        self._section_label(t("config"));    self._build_config_section()
        self._build_server_button()
        self._build_sleep_button()
        self._build_addresses_section()
        self._build_public_section()
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
            self._status_canvas.itemconfig(self._status_dot_id, fill="#22cc44")
            self._status_lbl.configure(text=t("online"), fg=FG())
            try:
                port = int(self._port_var.get())
            except ValueError:
                port = DEFAULT_PORT
            ws_port = port + 1 if HAS_WEBSOCKETS else None
            self._update_addr_block(port, ws_port)
            self._show_sleep_btn()

            if self._sleep_inhibit_enabled:
                self._sleep_btn.configure(text=f"☀  {t('keep_awake_on')}")
            else:
                self._sleep_btn.configure(text=f"☾  {t('keep_awake')}")

            if self._tunnel_url:
                self._draw_public_active(self._tunnel_url)
            elif self._tunnel_active:
                self._draw_public_connecting()
            else:
                self._draw_public_ready()

        self.after(0, lambda: self._canvas.yview_moveto(yview))

    # == Address block ==========================================================

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

    # == Placeholder / state draw helpers =======================================

    def _draw_offline_placeholder(self):
        for w in self._addr_frame.winfo_children():
            w.destroy()
        tk.Label(self._addr_frame, text=t("addresses_placeholder"),
                 font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=BG()).pack(anchor="w")

    def _draw_public_offline_placeholder(self):
        for w in self._public_section.winfo_children():
            w.destroy()
        tk.Label(self._public_section,
                 text=t("public_placeholder"),
                 font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=BG()).pack(anchor="w")

    def _draw_public_ready(self):
        for w in self._public_section.winfo_children():
            w.destroy()
        tk.Label(self._public_section,
                 text=t("public_ready"),
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=BG()
                 ).pack(anchor="w", pady=(0, self._s(8)))
        self._public_btn = tk.Button(
            self._public_section, text=t("share_publicly"),
            font=(FONT_MONO, self._fs(10), "bold"),
            fg=BG(), bg=FG(),
            activebackground=FG2(), activeforeground=BG(),
            relief="flat", bd=0, cursor="hand2", pady=self._s(12),
            command=self._start_tunnel,
        )
        self._public_btn.pack(fill="x")
        self._add_hover(self._public_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())

    def _draw_public_connecting(self):
        for w in self._public_section.winfo_children():
            w.destroy()
        tk.Label(self._public_section, text=f"*  {t('connecting')}",
                 font=(FONT_MONO, self._fs(9)), fg=FG2(), bg=BG()).pack(anchor="w")

    def _draw_public_reconnecting(self, delay: int, attempt: int):
        for w in self._public_section.winfo_children():
            w.destroy()
        tk.Label(self._public_section,
                 text=f"*  {t('reconnecting', delay=delay, attempt=attempt)}",
                 font=(FONT_MONO, self._fs(9)), fg=FG2(), bg=BG()).pack(anchor="w")
        tk.Button(
            self._public_section, text=t("stop"),
            font=(FONT_MONO, self._fs(8)),
            fg=FG(), bg=DANGER(),
            activebackground="#991111", activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(14), pady=self._s(6),
            command=self._stop_tunnel,
        ).pack(anchor="w", pady=(self._s(6), 0))

    def _draw_public_active(self, url: str):
        for w in self._public_section.winfo_children():
            w.destroy()

        badge_row = tk.Frame(self._public_section, bg=BG())
        badge_row.pack(fill="x", pady=(0, self._s(4)))
        dot_size = self._s(8)
        dot_cv   = tk.Canvas(badge_row, width=dot_size, height=dot_size,
                             bg=BG(), highlightthickness=0)
        dot_cv.pack(side="left", padx=(0, self._s(6)))
        dot_cv.create_oval(0, 0, dot_size, dot_size, fill="#22cc44", outline="")
        tk.Label(badge_row, text=t("live"),
                 font=(FONT_MONO, self._fs(8)), fg=FG2(), bg=BG()).pack(side="left")

        if self._tunnel_pw:
            pw_row = tk.Frame(self._public_section, bg=BG())
            pw_row.pack(fill="x", pady=(0, self._s(8)))
            tk.Label(pw_row, text=t("tunnel_pw"),
                     font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=BG()).pack(side="left")
            self._tpw_show = tk.BooleanVar(value=False)
            self._tpw_lbl  = tk.Label(pw_row, text="••••••••",
                                      font=(FONT_MONO, self._fs(8), "bold"),
                                      fg=FG2(), bg=BG())
            self._tpw_lbl.pack(side="left")

            def _toggle_tpw():
                if self._tpw_show.get():
                    self._tpw_lbl.config(text="••••••••")
                    self._tpw_show.set(False)
                    tpw_btn.config(text=t("show"))
                else:
                    self._tpw_lbl.config(text=self._tunnel_pw)
                    self._tpw_show.set(True)
                    tpw_btn.config(text=t("hide"))

            tpw_btn = tk.Button(pw_row, text=t("show"),
                                font=(FONT_MONO, self._fs(7)),
                                fg=FG3(), bg=BG(),
                                activeforeground=FG(), activebackground=BG(),
                                relief="flat", bd=0, cursor="hand2", padx=self._s(6),
                                command=_toggle_tpw)
            tpw_btn.pack(side="left", padx=(self._s(6), 0))

            local_pw_hint = self._password_var.get().strip()
            tk.Label(self._public_section,
                     text=t(
                         "local_pw_unchanged",
                         status=t("set") if local_pw_hint else t("none"),
                     ),
                     font=(FONT_MONO, self._fs(7)), fg=FG3(), bg=BG()
                     ).pack(anchor="w", pady=(0, self._s(6)))

        url_row = tk.Frame(self._public_section, bg=BG())
        url_row.pack(fill="x", pady=(0, self._s(8)))
        url_lbl = tk.Label(url_row, text=url,
                           font=(FONT_MONO, self._fs(9), "bold"),
                           fg=FG(), bg=BG(), cursor="hand2", anchor="w")
        url_lbl.pack(side="left", fill="x", expand=True)
        url_lbl.bind("<Button-1>", lambda e: self._copy(url))
        if HAS_QRCODE:
            tk.Button(url_row, text="QR", font=(FONT_MONO, self._fs(8)),
                      fg=FG3(), bg=BG(), activeforeground=FG(), activebackground=BG(),
                      relief="flat", bd=0, cursor="hand2", padx=self._s(8),
                      command=lambda: self._show_qr(url)).pack(side="right")
        tk.Button(url_row, text=t("copy"), font=(FONT_MONO, self._fs(8)),
                  fg=FG3(), bg=BG(), activeforeground=FG(), activebackground=BG(),
                  relief="flat", bd=0, cursor="hand2", padx=self._s(8),
                  command=lambda: self._copy(url)).pack(side="right")
        tk.Button(self._public_section, text=t("stop_sharing"),
                  font=(FONT_MONO, self._fs(9), "bold"),
                  fg=FG(), bg=DANGER(),
                  activebackground="#991111", activeforeground=FG(),
                  relief="flat", bd=0, cursor="hand2", pady=self._s(10),
                  command=self._stop_tunnel
                  ).pack(fill="x", pady=(self._s(4), 0))

    def _draw_public_error(self, msg: str):
        for w in self._public_section.winfo_children():
            w.destroy()
        tk.Label(self._public_section, text=f"✕  {msg}",
                 font=(FONT_MONO, self._fs(8)), fg=DANGER(), bg=BG(),
                 wraplength=self._win_w - self._s(60), justify="left"
                 ).pack(anchor="w", pady=(0, self._s(8)))
        retry_btn = tk.Button(
            self._public_section, text=t("retry"),
            font=(FONT_MONO, self._fs(9), "bold"),
            fg=BG(), bg=FG(),
            activebackground=FG2(), activeforeground=BG(),
            relief="flat", bd=0, cursor="hand2", pady=self._s(10),
            command=self._start_tunnel,
        )
        retry_btn.pack(fill="x")
        self._add_hover(retry_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())

    # == QR code popup ==========================================================

    def _show_qr(self, url: str):
        try:
            import qrcode as _qr
            from PIL import ImageTk, Image as _PilImg, ImageDraw
        except ImportError:
            messagebox.showinfo("QR Code", t("qr_install"))
            return

        QR_SIZE   = 260
        LOGO_FRAC = 0.22
        ico_path  = Path(__file__).parent.parent.parent / "favicon.ico"

        qr = _qr.QRCode(error_correction=_qr.constants.ERROR_CORRECT_H, box_size=10, border=4)
        qr.add_data(url); qr.make(fit=True)

        is_dark = _theme.get("BG", "#000") in ("#000000", "#0f0f0f", "#1a1a1a")
        qr_fg   = "#ffffff" if is_dark else "#0a0a0a"
        qr_bg   = "#000000" if is_dark else "#ffffff"

        img_pil  = qr.make_image(fill_color=qr_fg, back_color=qr_bg).convert("RGBA")
        img_pil  = img_pil.resize((QR_SIZE, QR_SIZE), _PilImg.LANCZOS)
        logo_px  = int(QR_SIZE * LOGO_FRAC)
        logo_img = None

        if ico_path.exists():
            try:
                raw     = _PilImg.open(ico_path).convert("RGBA")
                bg_img  = _PilImg.new("RGBA", (logo_px, logo_px), (0, 0, 0, 0))
                draw_bg = ImageDraw.Draw(bg_img)
                draw_bg.rounded_rectangle(
                    [0, 0, logo_px-1, logo_px-1], radius=logo_px//5,
                    fill=qr_bg+"ff" if len(qr_bg)==7 else qr_bg,
                )
                inner  = int(logo_px * 0.72)
                raw    = raw.resize((inner, inner), _PilImg.LANCZOS)
                offset = (logo_px - inner) // 2
                bg_img.paste(raw, (offset, offset), mask=raw)
                logo_img = bg_img
            except Exception:
                logo_img = None

        if logo_img is None:
            from PIL import ImageFont
            logo_img = _PilImg.new("RGBA", (logo_px, logo_px), (0, 0, 0, 0))
            draw     = ImageDraw.Draw(logo_img)
            draw.rounded_rectangle([0, 0, logo_px-1, logo_px-1], radius=logo_px//5, fill=qr_fg)
            font_size = max(10, logo_px // 2); fnt = None
            for fp in [
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
                "/System/Library/Fonts/Courier.ttc",
                "C:/Windows/Fonts/cour.ttf",
            ]:
                try:
                    fnt = ImageFont.truetype(fp, font_size); break
                except Exception:
                    pass
            if fnt is None:
                fnt = ImageFont.load_default()
            bbox = draw.textbbox((0, 0), "NS", font=fnt)
            draw.text(
                ((logo_px-(bbox[2]-bbox[0]))//2-bbox[0],
                 (logo_px-(bbox[3]-bbox[1]))//2-bbox[1]),
                "NS", font=fnt, fill=qr_bg,
            )

        img_pil.paste(logo_img, ((QR_SIZE-logo_px)//2, (QR_SIZE-logo_px)//2), mask=logo_img)
        img_tk = ImageTk.PhotoImage(img_pil)

        win = tk.Toplevel(self)
        win.title(t("qr_title"))
        win.configure(bg=BG())
        win.resizable(False, False)
        if ico_path.exists():
            try:
                win.iconbitmap(str(ico_path))
            except Exception:
                pass
        frame = tk.Frame(win, bg=FG(), padx=self._s(16), pady=self._s(16))
        frame.pack(padx=self._s(24), pady=(self._s(24), self._s(12)))
        tk.Label(frame, image=img_tk, bg=FG()).pack()
        win._img_ref = img_tk
        tk.Label(win, text=url, font=(FONT_MONO, self._fs(9)),
                 fg=FG3(), bg=BG()).pack(pady=(0, self._s(16)))

    # == Log helpers ============================================================

    def _log(self, msg: str, kind: str = "info"):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_text.configure(state="normal")
        self._log_text.insert("end", f"[{ts}]  ", "ts")
        self._log_text.insert("end", f"{msg}\n", kind)
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def _copy(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._log(f"copied  {text}", "dim")

    # == Log drainer ============================================================

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
        if getattr(self, "_drainer_active", False):
            self.after(50, self._drain_log_queue)

    # == Sleep inhibitor toggle =================================================

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

    # == Folder actions =========================================================

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
            self._log(f"ROOT   changed → {state.ROOT_DIR}", "info")

    # == Server lifecycle =======================================================

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
        _file_index.clear()

        state._log_callback = lambda msg, kind="info": None
        self._start_log_drainer()

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
            self._log("websockets not installed — persistent connection disabled", "dim")
            self._log("→  pip install websockets", "dim")

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

        self._toggle_btn.configure(text=t("stop_server"), bg=DANGER())
        self._add_hover(self._toggle_btn, DANGER(), "#991111",
                        text_normal=FG(), text_hover=FG())
        self._toggle_btn.configure(fg=FG())
        self._status_canvas.itemconfig(self._status_dot_id, fill="#22cc44")
        self._status_lbl.configure(text=t("online"), fg=FG())
        self._update_addr_block(port, ws_port if HAS_WEBSOCKETS else None)
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

        self._stop_log_drainer()
        self._log("server stopped", "dim")
        self._toggle_btn.configure(text=t("start_server"), bg=FG(), fg=BG())
        self._add_hover(self._toggle_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())
        self._status_canvas.itemconfig(self._status_dot_id, fill=FG3())
        self._status_lbl.configure(text=t("offline"), fg=FG3())
        self._draw_offline_placeholder()
        self._draw_public_offline_placeholder()
        self._hide_sleep_btn()

    # == Tunnel lifecycle =======================================================

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

        pw = ask_tunnel_password(self)
        if pw is None:
            return

        self._tunnel_pw       = pw
        state.TUNNEL_PASSWORD = pw
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
        self.after(0, lambda: self._log(f"TUNNEL live → {url}", "ok"))
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
            f"TUNNEL lost — reconnecting in {delay}s (attempt {attempt})", "dim"
        ))

    # == Window close ===========================================================

    def _on_close(self):
        if self._tunnel_active or self._tunnel:
            self._stop_tunnel()
        if self._sleep_inhibit_enabled:
            inhibit_sleep(False)
        if self._running:
            self._stop_server()
        self.destroy()
