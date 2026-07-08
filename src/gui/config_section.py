"""Reusable GUI section builders for ConfigSectionMixin."""

from pathlib import Path

import tkinter as tk

from src.constants import VERSION, MAX_HISTORY, FONT_MONO
from src.i18n import LANGUAGES, t
from src.theme import _theme, BG, SURFACE, SURFACE2, BORDER, FG, FG2, FG3


class ConfigSectionMixin:

    # Config section

    def _build_config_section(self):
        self._write_option_widgets = []
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

        # Local password row
        pw_row = tk.Frame(self._body, bg=BG())
        pw_row.pack(fill="x", padx=self._s(24), pady=(self._s(6), 0))

        tk.Label(pw_row, text=t("local_pw"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=BG()).pack(side="left", padx=(0, self._s(6)))

        self._pw_entry = tk.Entry(
            pw_row, textvariable=self._password_var,
            font=(FONT_MONO, self._fs(10)), fg=FG(), bg=SURFACE(),
            insertbackground=FG(), relief="flat", bd=0, width=16,
            highlightthickness=1, highlightbackground=BORDER(), show="-",
        )
        self._pw_entry.pack(side="left", ipady=self._s(8), padx=(0, self._s(6)))
        self._pw_entry.bind("<FocusIn>",  lambda e: self._pw_entry.config(highlightbackground=FG()))
        self._pw_entry.bind("<FocusOut>", lambda e: self._pw_entry.config(highlightbackground=BORDER()))

        self._pw_show_var = tk.BooleanVar(value=False)

        def _toggle_pw_visibility():
            if self._pw_show_var.get():
                self._pw_entry.config(show="-")
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

        # Write permissions
        perm_row = tk.Frame(self._body, bg=BG())
        perm_row.pack(fill="x", padx=self._s(24), pady=(self._s(10), 0))

        tk.Label(
            perm_row,
            text=t("write_permissions"),
            font=(FONT_MONO, self._fs(8)),
            fg=FG3(), bg=BG(),
        ).pack(anchor="w", pady=(0, self._s(4)))

        def _permission_check(label, variable):
            cb = tk.Checkbutton(
                perm_row,
                text=label,
                variable=variable,
                font=(FONT_MONO, self._fs(8)),
                fg=FG2(), bg=BG(),
                activeforeground=FG(), activebackground=BG(),
                selectcolor=SURFACE(),
                relief="flat", bd=0, cursor="hand2",
                highlightthickness=0,
                anchor="w",
            )
            self._responsive_wrap(cb, padding=72)
            cb.pack(fill="x", anchor="w")
            self._write_option_widgets.append(cb)
            return cb

        self._upload_cb = _permission_check(t("allow_receiving_files"), self._allow_upload_var)
        self._edit_cb   = _permission_check(t("allow_document_edits"),  self._allow_edit_var)

        # Apply cached remote flags immediately (in case of language rebuild)
        self._apply_remote_flags_to_ui()
