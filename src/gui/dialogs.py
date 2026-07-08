"""
Reusable Tkinter dialogs for NetShare Server.
"""

import tkinter as tk
from tkinter import messagebox

from src.constants import FONT_MONO
from src.i18n import t
from src.theme import BG, SURFACE, BORDER, FG, FG2, FG3, DANGER


def ask_tunnel_password(parent) -> str | None:
    """
    Modal dialog that asks the user to set a tunnel access password.

    Returns the entered password string, or None if the user cancelled.
    The field has a show/hide toggle.
    The password is required - cannot be left empty (prevents open public access).
    """
    result = {"value": None}

    dlg = tk.Toplevel(parent)
    dlg.title(t("set_tunnel_password_title"))
    dlg.configure(bg=BG())
    dlg.resizable(False, False)
    dlg.grab_set()

    s = parent._s

    # Header
    tk.Label(
        dlg,
        text=t("tunnel_access_password"),
        font=(FONT_MONO, parent._fs(10), "bold"),
        fg=FG(), bg=BG(),
    ).pack(padx=s(24), pady=(s(24), s(4)), anchor="w")

    tk.Label(
        dlg,
        text=t("tunnel_password_help"),
        font=(FONT_MONO, parent._fs(8)),
        fg=FG2(), bg=BG(), justify="left",
    ).pack(padx=s(24), pady=(0, s(16)), anchor="w")

    # Password row
    pw_row   = tk.Frame(dlg, bg=BG())
    pw_row.pack(fill="x", padx=s(24), pady=(0, s(6)))

    pw_var   = tk.StringVar()
    show_var = tk.BooleanVar(value=False)

    pw_entry = tk.Entry(
        pw_row,
        textvariable=pw_var,
        show="-",
        font=(FONT_MONO, parent._fs(11)),
        fg=FG(), bg=SURFACE(),
        insertbackground=FG(),
        relief="flat", bd=0,
        highlightthickness=1,
        highlightbackground=BORDER(),
    )
    pw_entry.pack(side="left", fill="x", expand=True, ipady=s(10))
    pw_entry.bind("<FocusIn>",  lambda e: pw_entry.config(highlightbackground=FG()))
    pw_entry.bind("<FocusOut>", lambda e: pw_entry.config(highlightbackground=BORDER()))

    def _toggle_show():
        if show_var.get():
            pw_entry.config(show="-")
            show_btn.config(text=t("show"))
        else:
            pw_entry.config(show="")
            show_btn.config(text=t("hide"))
        show_var.set(not show_var.get())

    show_btn = tk.Button(
        pw_row,
        text=t("show"),
        font=(FONT_MONO, parent._fs(8)),
        fg=FG3(), bg=BG(),
        activeforeground=FG(), activebackground=BG(),
        relief="flat", bd=0, cursor="hand2",
        padx=s(10),
        command=_toggle_show,
    )
    show_btn.pack(side="right", padx=(s(8), 0))

    # Error label (hidden until needed)
    err_lbl = tk.Label(
        dlg, text="",
        font=(FONT_MONO, parent._fs(8)),
        fg=DANGER(), bg=BG(),
    )
    err_lbl.pack(padx=s(24), anchor="w")

    # Buttons
    btn_row = tk.Frame(dlg, bg=BG())
    btn_row.pack(fill="x", padx=s(24), pady=(s(12), s(24)))

    def _cancel():
        result["value"] = None
        dlg.destroy()

    def _confirm():
        pw = pw_var.get().strip()
        if not pw:
            err_lbl.config(text=t("password_required"))
            pw_entry.focus_set()
            return
        if len(pw) < 8:
            err_lbl.config(text=t("password_too_short"))
            pw_entry.focus_set()
            return
        result["value"] = pw
        dlg.destroy()

    tk.Button(
        btn_row,
        text=t("cancel"),
        font=(FONT_MONO, parent._fs(9)),
        fg=FG3(), bg=BG(),
        activeforeground=FG(), activebackground=FG3(),
        relief="flat", bd=0, cursor="hand2",
        padx=s(16), pady=s(10),
        command=_cancel,
    ).pack(side="left")

    tk.Button(
        btn_row,
        text=t("start_sharing"),
        font=(FONT_MONO, parent._fs(9), "bold"),
        fg=BG(), bg=FG(),
        activebackground=FG2(), activeforeground=BG(),
        relief="flat", bd=0, cursor="hand2",
        padx=s(16), pady=s(10),
        command=_confirm,
    ).pack(side="right")

    # Keyboard shortcuts
    dlg.bind("<Return>", lambda e: _confirm())
    dlg.bind("<Escape>", lambda e: _cancel())

    # Centre over parent
    parent.update_idletasks()
    dlg.update_idletasks()
    px = parent.winfo_x() + (parent.winfo_width()  - dlg.winfo_width())  // 2
    py = parent.winfo_y() + (parent.winfo_height() - dlg.winfo_height()) // 2
    dlg.geometry(f"+{px}+{py}")

    pw_entry.focus_set()
    dlg.wait_window()
    return result["value"]
