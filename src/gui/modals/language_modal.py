"""
Languages modal -- replaces the inline tk.OptionMenu that used to live in
HeaderSectionMixin._build_header(). It only changes *how* a language gets
picked; _change_language() (RemoteFlagsMixin) stays the handler, unchanged,
so the existing rebuild-on-language-switch pattern keeps working as-is.
"""

import tkinter as tk

from src.constants import FONT_MONO
from src.i18n import LANGUAGES, t
from src.theme import SURFACE, SURFACE2, FG, FG2


class LanguageModalMixin:

    def _open_language_modal(self):
        self._show_modal(t("language"), self._build_language_modal_content, width=260, height=360)

    def _build_language_modal_content(self, parent, close_fn):
        canvas = tk.Canvas(parent, bg=SURFACE(), highlightthickness=0)
        scrollbar = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        list_frame = tk.Frame(canvas, bg=SURFACE())
        window_id = canvas.create_window((0, 0), window=list_frame, anchor="nw")

        def _on_configure(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(window_id, width=canvas.winfo_width())
        list_frame.bind("<Configure>", _on_configure)
        canvas.bind("<Configure>", _on_configure)

        current = self._language_var.get()
        for code, label in LANGUAGES.items():
            is_current = code == current
            row = tk.Button(
                list_frame, text=label,
                font=(FONT_MONO, self._fs(10), "bold" if is_current else "normal"),
                fg=FG() if is_current else FG2(),
                bg=SURFACE2() if is_current else SURFACE(),
                activebackground=SURFACE2(), activeforeground=FG(),
                relief="flat", bd=0, cursor="hand2", anchor="w",
                padx=self._s(12), pady=self._s(9),
                command=lambda c=code: self._select_language_from_modal(c, close_fn),
            )
            row.pack(fill="x", pady=(0, self._s(2)))
            self._add_hover(row, SURFACE2() if is_current else SURFACE(), SURFACE2(),
                             text_normal=FG() if is_current else FG2(), text_hover=FG())

    def _select_language_from_modal(self, code: str, close_fn):
        close_fn()
        self._change_language(code)
