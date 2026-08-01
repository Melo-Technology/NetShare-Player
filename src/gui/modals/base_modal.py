"""
Shared modal machinery: a backdrop + a centered modal window, reused
by every Settings-style popup (Languages, Settings).

FIX (reported bug: clicking anything inside the modal closed it instead of
activating it): the original version used two separate Toplevel windows --
a dim overlay and the modal on top of it -- and relied on window-manager
stacking order to keep the modal above the overlay. That stacking is not
reliably guaranteed across window managers; on at least one reported setup
the overlay ended up receiving clicks meant for the modal, since overlay
and modal are two independent top-level surfaces from the WM's point of
view. Two separate Toplevels also fought over -topmost/lift() in a way
that made the ordering non-deterministic after the first open.

Fix: a single Toplevel for the backdrop, with the modal built as a
plain Frame *inside* that same Toplevel, positioned with place(). Because
both live in one Tk widget tree, Tk's own (reliable) widget stacking
decides what's on top at a given pixel -- no window-manager involvement,
no ambiguity. The click-catcher (closes on click) is a Frame sibling
placed first (bottom); the modal Frame is placed after it and explicitly
raised, so any click physically over the modal hits the modal's widgets,
never the catcher underneath.

Both live under `self` (the main App/Tk window), so ThemeMixin._repaint_all()
still reaches them for free on a theme toggle, as long as modal content
sticks to the same BG()/FG()/SURFACE()/... accessors as the rest of the app.
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
        # Tk applies Toplevel alpha to every child widget too. Keeping the
        # backdrop opaque avoids making the modal content itself transparent.
        overlay.geometry(f"{root_w}x{root_h}+{root_x}+{root_y}")
        overlay.bind("<Escape>", lambda e: self._close_modal())
        self._modal_overlay = overlay

        # Click-catcher: covers the whole overlay, sits BEHIND the modal frame
        # (placed/raised first). A click anywhere the modal isn't closes it.
        catcher = tk.Frame(overlay, bg=BG())
        catcher.place(x=0, y=0, relwidth=1, relheight=1)
        catcher.bind("<Button-1>", lambda e: self._close_modal())

        # Modal frame -- a child of the SAME window as the catcher, so Tk's
        # own widget stacking (not the WM's) decides who gets the click.
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
        modal.lift()  # belt-and-suspenders: later-placed siblings are already on top by default
        # A click that lands on the modal frame itself (not one of its
        # children/buttons) must not fall through to the catcher's binding.
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

        overlay.focus_set()  # so <Escape> (bound on the overlay) actually fires
        return modal

    def _close_modal(self):
        # Destroying the overlay Toplevel destroys the modal Frame with it
        # (it's a child) -- nothing to separately destroy.
        if self._modal_overlay is not None:
            try:
                self._modal_overlay.destroy()
            except Exception:
                pass
            self._modal_overlay = None
        self._modal_window = None
