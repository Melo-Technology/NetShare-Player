"""
NetShare Player — Theme-toggle mixin for the App widget.

Provides _toggle_theme(), _repaint_all(), and the colour-swap helpers
that live-update every child widget when the user switches dark ↔ light.
"""

from src.theme import _theme, _DARK, _LIGHT, BG, FG, FG2, FG3, BORDER, SURFACE, DANGER


class ThemeMixin:
    """
    Mix into App (tk.Tk) to add dark/light live-toggle behaviour.
    Requires self._dark_mode (bool) and self._theme_btn to be set by App.__init__.
    """

    # == Public toggle ==========================================================

    def _toggle_theme(self):
        self._dark_mode = not self._dark_mode
        _theme.update(_DARK if self._dark_mode else _LIGHT)
        self._theme_btn.configure(
            text="☀" if self._dark_mode else "☾",
            bg=_theme["TOGGLE_BG"],   fg=_theme["TOGGLE_FG"],
            activebackground=_theme["TOGGLE_BG"], activeforeground=FG(),
        )
        self.configure(bg=BG())
        self._repaint_all(self)

    # == Recursive repaint ======================================================

    def _repaint_all(self, widget):
        self._repaint_widget(widget)
        for child in widget.winfo_children():
            self._repaint_all(child)

    def _repaint_widget(self, w):
        cls = w.winfo_class()
        try:
            if cls in ("Frame", "Label", "Button", "Canvas", "Menubutton"):
                self._recolour(w, "bg")
            if cls in ("Label", "Button", "Menubutton"):
                self._recolour(w, "fg")
            if cls in ("Button", "Menubutton"):
                self._recolour(w, "activebackground")
                self._recolour(w, "activeforeground")
            if cls == "Entry":
                for opt in ("bg", "fg", "insertbackground", "highlightbackground"):
                    self._recolour(w, opt)
            if cls == "Text":
                self._recolour(w, "bg")
                self._recolour(w, "fg")
                try:
                    w.tag_configure("info",  foreground=FG2())
                    w.tag_configure("ok",    foreground=FG())
                    w.tag_configure("error", foreground=DANGER())
                    w.tag_configure("dim",   foreground=FG3())
                    w.tag_configure("ts",    foreground=FG3())
                except Exception:
                    pass
            if cls == "Scrollbar":
                w.configure(bg=BG(), troughcolor=SURFACE(), activebackground=FG3())
        except Exception:
            pass

    # == Colour helpers =========================================================

    def _swap(self, colour: str) -> str:
        """Map a hex colour from the old palette to the new one."""
        old = _LIGHT if self._dark_mode else _DARK
        new = _DARK  if self._dark_mode else _LIGHT
        c   = colour.lower()
        for key, val in old.items():
            if c == val.lower() and key in new:
                return new[key]
        return colour

    def _recolour(self, widget, option: str):
        try:
            cur = widget.cget(option)
            if isinstance(cur, str) and cur.startswith("#"):
                nw = self._swap(cur)
                if nw != cur:
                    widget.configure(**{option: nw})
        except Exception:
            pass
