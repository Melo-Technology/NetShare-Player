"""LayoutMixin extracted from the main GUI window."""

import tkinter as tk

from src.constants import FONT_MONO
from src.i18n import t
from src.theme import BG, SURFACE, SURFACE2, BORDER, FG, FG2, FG3, DANGER
from src.utils.platform import PLATFORM


class LayoutMixin:

    # UI construction

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
            self._win_w = e.width
            self._canvas.itemconfig(self._body_win_id, width=e.width)
            self._update_responsive_texts(e.width)
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
        self._build_server_button()
        self._build_addresses_section()
        self._build_incoming_section()
        self._build_log_section()
        self._build_footer()
        self._apply_remote_flags_to_ui()

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

    # Sleep / keep-awake button

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

    # Addresses section

    def _build_addresses_section(self):
        self._section_label(t("addresses"))
        self._addr_frame = tk.Frame(self._body, bg=BG())
        self._addr_frame.pack(fill="x", padx=self._s(24), pady=(0, self._s(6)))
        self._draw_offline_placeholder()

    # Write pairing section

    def _build_write_pairing_section(self):
        self._write_pairing_outer = tk.Frame(self._body, bg=BG())
        self._write_pairing_outer.pack(fill="x")
        self._section_label_in(self._write_pairing_outer, t("local_pairing"))
        self._write_pairing_frame = tk.Frame(self._write_pairing_outer, bg=BG())
        self._write_pairing_frame.pack(fill="x", padx=self._s(24), pady=(0, self._s(6)))
        self._draw_write_pairing_placeholder()

    def _build_public_section(self):
        self._public_outer = tk.Frame(self._body, bg=BG())
        self._public_outer.pack(fill="x")
        self._section_label_in(self._public_outer, t("public_sharing"))
        self._public_section = tk.Frame(self._public_outer, bg=BG())
        self._public_section.pack(fill="x", padx=self._s(24), pady=(0, self._s(6)))
        self._draw_public_offline_placeholder()

    # Log section

    def _build_log_section(self):
        self._section_label(t("log"))
        log_outer = tk.Frame(self._body, bg=SURFACE(),
                             highlightthickness=1, highlightbackground=BORDER())
        log_outer.pack(fill="x", padx=self._s(24), pady=(0, self._s(12)))

        actions = tk.Frame(log_outer, bg=SURFACE())
        actions.pack(fill="x", padx=self._s(8), pady=(self._s(7), 0))
        tk.Button(
            actions,
            text=t("export_logs"),
            font=(FONT_MONO, self._fs(7), "bold"),
            fg=FG(), bg=SURFACE2(),
            activeforeground=BG(), activebackground=FG(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(10), pady=self._s(5),
            command=self._export_logs,
        ).pack(side="right")

        log_content = tk.Frame(log_outer, bg=SURFACE())
        log_content.pack(fill="both", expand=True)
        self._log_text = tk.Text(
            log_content, height=9, bg=SURFACE(), fg=FG2(),
            font=(FONT_MONO, self._fs(9)), relief="flat", bd=0,
            padx=self._s(12), pady=self._s(10),
            state="disabled", insertbackground=FG(), wrap="word", cursor="arrow",
        )
        log_scrollbar = tk.Scrollbar(
            log_content, orient="vertical", command=self._log_text.yview,
            bg=BG(), troughcolor=SURFACE(), activebackground=FG3(),
        )
        self._log_text.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.pack(side="right", fill="y")
        self._log_text.pack(side="left", fill="both", expand=True)

        def _scroll_log(event):
            if event.num == 4:
                units = -1
            elif event.num == 5:
                units = 1
            else:
                units = int(-1 * (event.delta / 120)) if PLATFORM == "windows" else int(-1 * event.delta)
            self._log_text.yview_scroll(units, "units")
            return "break"

        self._log_text.bind("<MouseWheel>", _scroll_log)
        self._log_text.bind("<Button-4>", _scroll_log)
        self._log_text.bind("<Button-5>", _scroll_log)
        self._log_text.tag_configure("info",  foreground=FG2())
        self._log_text.tag_configure("ok",    foreground=FG())
        self._log_text.tag_configure("error", foreground=DANGER())
        self._log_text.tag_configure("dim",   foreground=FG3())
        self._log_text.tag_configure("ts",    foreground=FG3())

    # Incoming activity section

    def _build_incoming_section(self):
        self._incoming_outer = tk.Frame(self._body, bg=BG())
        self._incoming_outer.pack(fill="x")
        self._section_label_in(self._incoming_outer, t("incoming"))
        self._pending_uploads_frame = tk.Frame(self._incoming_outer, bg=BG())
        self._pending_uploads_frame.pack(fill="x", padx=self._s(24))
        incoming_frame = tk.Frame(
            self._incoming_outer,
            bg=SURFACE(),
            highlightthickness=1,
            highlightbackground=BORDER(),
        )
        incoming_frame.pack(fill="x", padx=self._s(24), pady=(0, self._s(6)))
        self._incoming_text = tk.Text(
            incoming_frame,
            height=5,
            bg=SURFACE(), fg=FG2(),
            font=(FONT_MONO, self._fs(8)),
            relief="flat", bd=0,
            padx=self._s(12), pady=self._s(8),
            state="disabled", insertbackground=FG(), wrap="word", cursor="arrow",
        )
        self._incoming_text.pack(fill="x")
        self._incoming_text.tag_configure("info",  foreground=FG2())
        self._incoming_text.tag_configure("ok",    foreground=FG())
        self._incoming_text.tag_configure("dim",   foreground=FG3())
        self._incoming_text.tag_configure("error", foreground=DANGER())
        self._add_incoming_line(t("incoming_placeholder"), "dim")

    # Footer

    def _build_footer(self):
        footer_frame = tk.Frame(self._body, bg=BG(),
                                highlightthickness=1, highlightbackground=BORDER())
        footer_frame.pack(fill="x", padx=self._s(24), pady=(0, self._s(24)))
        self._responsive_wrap(tk.Label(
            footer_frame,
            text=f"!  {t('footer_warning')}",
            font=(FONT_MONO, self._fs(8)),
            fg=DANGER(), bg=BG(), pady=self._s(8),
        ), padding=72).pack(fill="x", padx=self._s(8))

    # Shared layout helpers

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
    def _section_label_in(self, parent: tk.Frame, text: str):
        """Variante de _section_label qui pack dans `parent` plutôt que dans self._body."""
        frame = tk.Frame(parent, bg=BG())
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


    def _responsive_wrap(self, widget, padding=64):
        if not hasattr(self, "_responsive_text_widgets"):
            self._responsive_text_widgets = []
        self._responsive_text_widgets.append((widget, padding))
        widget.configure(justify="left")
        self._update_responsive_texts()
        return widget

    def _update_responsive_texts(self, width=None):
        if not hasattr(self, "_responsive_text_widgets"):
            return
        if width is None:
            try:
                width = self._canvas.winfo_width()
            except tk.TclError:
                width = self._win_w
        live_widgets = []
        for widget, padding in self._responsive_text_widgets:
            try:
                if not widget.winfo_exists():
                    continue
                wraplength = max(self._s(120), int(width) - self._s(padding))
                widget.configure(wraplength=wraplength)
                live_widgets.append((widget, padding))
            except tk.TclError:
                continue
        self._responsive_text_widgets = live_widgets


    def _set_write_options_enabled(self, enabled: bool):
        state_name = "normal" if enabled else "disabled"
        for widget in getattr(self, "_write_option_widgets", []):
            try:
                widget.configure(state=state_name)
            except Exception:
                pass

