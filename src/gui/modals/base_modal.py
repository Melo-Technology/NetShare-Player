"""
Shared modal machinery: a backdrop + a centered modal window, reused
by every Settings-style popup (Languages, Settings).
"""

import tkinter as tk

from src.constants import FONT_MONO
from src.theme import BG, SURFACE, BORDER, FG, FG3


class ModalMixin:
    """
    Mix into App. _show_modal() is the single entry point every concrete
    modal builds on top of -- it does not know or care what it's showing.
    """

    _modal_overlay: tk.Toplevel | None = None   # the single Toplevel (backdrop)
    _modal_window: tk.Frame | None = None        # the modal Frame, child of the overlay

    def _show_modal(self, title: str, build_content, width: int = 360, height: int = 420):
        """
        build_content(content_frame, close_fn) populates the modal body.
        close_fn is handed down so content (e.g. "pick this language") can
        close the modal itself after acting, without importing this mixin.
        """
        self._close_modal()  # only one modal at a time

        root_w = self.winfo_width() or self._win_w
        root_h = self.winfo_height() or self._win_h
        root_x = self.winfo_rootx()
        root_y = self.winfo_rooty()

        overlay = tk.Toplevel(self)
        overlay.overrideredirect(True)
        overlay.configure(bg=BG())
        
        overlay.geometry(f"{root_w}x{root_h}+{root_x}+{root_y}")
        overlay.bind("<Escape>", lambda e: self._close_modal())
        self._modal_overlay = overlay

        catcher = tk.Frame(overlay, bg=BG())
        catcher.place(x=0, y=0, relwidth=1, relheight=1)
        catcher.bind("<Button-1>", lambda e: self._close_modal())

        
        margin_x = min(self._s(16), max(0, (root_w - 1) // 2))
        margin_y = min(self._s(16), max(0, (root_h - 1) // 2))
        available_w = max(1, root_w - (margin_x * 2))
        available_h = max(1, root_h - (margin_y * 2))
        w = min(self._s(width), available_w)
        h = min(self._s(height), available_h)
        x = max(margin_x, (root_w - w) // 2)
        y = max(margin_y, (root_h - h) // 2)
        modal = tk.Frame(overlay, bg=SURFACE(), highlightthickness=1, highlightbackground=BORDER())
        modal.place(x=x, y=y, width=w, height=h)
        modal.lift()  
        modal.bind("<Button-1>", lambda e: "break")
        self._modal_window = modal

        header = tk.Frame(modal, bg=SURFACE())
        header.pack(fill="x", padx=self._s(16), pady=(self._s(14), 0))
        tk.Label(
            header, text=title, font=(FONT_MONO, self._fs(11), "bold"),
            fg=FG(), bg=SURFACE(),
        ).pack(side="left")
        tk.Button(
            header, text="\u2715", font=(FONT_MONO, self._fs(10)),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            command=self._close_modal,
        ).pack(side="right")

        tk.Frame(modal, bg=BORDER(), height=1).pack(fill="x", padx=self._s(16), pady=(self._s(10), 0))

        content = tk.Frame(modal, bg=SURFACE())
        content.pack(fill="both", expand=True, padx=self._s(16), pady=self._s(12))

        overlay.update_idletasks()
        build_content(content, self._close_modal)

        overlay.focus_set()  
        return modal

    def _close_modal(self):
        if self._modal_overlay is not None:
            try:
                self._modal_overlay.destroy()
            except Exception:
                pass
            self._modal_overlay = None
        self._modal_window = None
