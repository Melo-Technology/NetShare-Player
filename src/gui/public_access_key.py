"""Public access key widgets for the sharing panel."""

import tkinter as tk

from src.constants import FONT_MONO
from src.i18n import t
from src.theme import BG, SURFACE, BORDER, FG, FG2, FG3


class PublicAccessKeyMixin:
    def _draw_public_access_key(self, title: str, key: str, description: str):
        row = tk.Frame(
            self._public_section,
            bg=SURFACE(),
            highlightthickness=1,
            highlightbackground=BORDER(),
        )
        row.pack(fill="x", pady=(0, self._s(6)))

        top = tk.Frame(row, bg=SURFACE())
        top.pack(fill="x", padx=self._s(10), pady=(self._s(8), 0))
        tk.Label(top, text=title,
                 font=(FONT_MONO, self._fs(8), "bold"),
                 fg=FG(), bg=SURFACE()).pack(anchor="w")
        self._responsive_wrap(tk.Label(top, text=description,
                 font=(FONT_MONO, self._fs(7)),
                 fg=FG3(), bg=SURFACE()), padding=96).pack(anchor="w", fill="x", pady=(self._s(2), 0))

        value_row = tk.Frame(row, bg=SURFACE())
        value_row.pack(fill="x", padx=self._s(10), pady=(self._s(4), self._s(8)))
        visible = tk.BooleanVar(value=False)
        label = tk.Label(value_row,
                         text=t("not_set") if not key else "********",
                         font=(FONT_MONO, self._fs(8), "bold"),
                         fg=FG2() if key else FG3(),
                         bg=SURFACE())
        label.pack(side="left", fill="x", expand=True, anchor="w")

        def _toggle():
            if not key:
                return
            visible.set(not visible.get())
            label.config(text=key if visible.get() else "********")
            show_btn.config(text=t("hide") if visible.get() else t("show"))

        show_btn = tk.Button(value_row, text=t("show"),
                             font=(FONT_MONO, self._fs(7)),
                             fg=FG3(), bg=SURFACE(),
                             activeforeground=FG(), activebackground=SURFACE(),
                             relief="flat", bd=0, cursor="hand2",
                             padx=self._s(6), command=_toggle)
        show_btn.pack(side="right")
        tk.Button(value_row, text=t("copy"),
                  font=(FONT_MONO, self._fs(7)),
                  fg=FG3(), bg=SURFACE(),
                  activeforeground=FG(), activebackground=SURFACE(),
                  relief="flat", bd=0, cursor="hand2",
                  padx=self._s(6),
                  command=lambda: self._copy(key) if key else None
                  ).pack(side="right")

