"""Reusable GUI section builders for HeaderSectionMixin."""

from pathlib import Path

import tkinter as tk

from src.constants import VERSION, MAX_HISTORY, FONT_MONO
from src.i18n import LANGUAGES, t
from src.theme import _theme, BG, SURFACE, SURFACE2, BORDER, FG, FG2, FG3


class HeaderSectionMixin:

    # Header

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

        self._firebase_lbl = None

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

    # Folder section

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
