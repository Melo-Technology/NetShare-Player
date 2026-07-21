"""
Sidebar drawer (hamburger menu) -- slides in from the left over the main
content: Languages, Settings, an inline Theme toggle, and a footer pinned
to the bottom with the server/PC name + version (moved here from the old
footer, per the GUI restructuring plan).

Implemented as plain Frames placed with place() *inside the main window*
(self), not as a separate Toplevel -- this is what makes a smooth slide
animation practical: moving a widget's x-coordinate frame by frame inside
one window is cheap and consistent across platforms, whereas animating two
separate window-manager-controlled Toplevel surfaces in lockstep tends to
tear or lag on at least one of Windows/macOS/Linux.

Animation is a small after()-driven position loop. _SIDEBAR_ANIMATE is the
single switch to fall back to an instant show/hide if this turns out
choppy on a given platform -- flip it without touching anything else here.
"""

import socket
import tkinter as tk

from src.constants import VERSION, FONT_MONO
from src.i18n import t
from src.theme import SURFACE, SURFACE2, BORDER, FG, FG2, FG3

_SIDEBAR_ANIMATE = True
_SIDEBAR_STEPS = 10
_SIDEBAR_STEP_MS = 12


class SidebarMixin:

    _sidebar_frame: tk.Frame | None = None
    _sidebar_dim: tk.Frame | None = None
    _sidebar_open = False
    _sidebar_anim_job = None
    _sidebar_theme_toggle_btn: tk.Button | None = None

    # Hamburger icon, built into the header

    def _build_sidebar_toggle(self, parent) -> tk.Button:
        from src.theme import BG
        return tk.Button(
            parent, text="\u2630", font=(FONT_MONO, self._fs(12)),
            fg=FG(), bg=BG(), activebackground=BG(), activeforeground=FG2(),
            relief="flat", bd=0, cursor="hand2", padx=self._s(4),
            command=self._toggle_sidebar,
        )

    def _toggle_sidebar(self):
        self._close_sidebar() if self._sidebar_open else self._open_sidebar()

    # Open / close

    def _open_sidebar(self):
        if self._sidebar_open:
            return
        self._sidebar_open = True

        width = self._s(220)
        win_w = self.winfo_width() or self._win_w
        win_h = self.winfo_height() or self._win_h

        dim = tk.Frame(self, bg=BORDER())
        dim.place(x=0, y=0, width=win_w, height=win_h)
        dim.bind("<Button-1>", lambda e: self._close_sidebar())
        self._sidebar_dim = dim

        panel = tk.Frame(self, bg=SURFACE(), highlightthickness=1, highlightbackground=BORDER())
        panel.place(x=-width, y=0, width=width, height=win_h)
        self._sidebar_frame = panel
        self._build_sidebar_content(panel)

        dim.lift()
        panel.lift()

        self.bind("<Escape>", self._on_escape_close_sidebar)
        self.bind("<Configure>", self._on_root_resize_sidebar, add="+")

        if _SIDEBAR_ANIMATE:
            self._animate_sidebar(width, target_x=0)
        else:
            panel.place_configure(x=0)

    def _on_escape_close_sidebar(self, _event=None):
        self._close_sidebar()

    def _close_sidebar(self):
        if not self._sidebar_open:
            return
        self._sidebar_open = False
        width = (self._sidebar_frame.winfo_width()
                 if self._sidebar_frame is not None else self._s(220))

        def _finish():
            if self._sidebar_frame is not None:
                self._sidebar_frame.destroy()
                self._sidebar_frame = None
            if self._sidebar_dim is not None:
                self._sidebar_dim.destroy()
                self._sidebar_dim = None

        if _SIDEBAR_ANIMATE and self._sidebar_frame is not None:
            self._animate_sidebar(width, target_x=-width, on_done=_finish)
        else:
            _finish()

    def _animate_sidebar(self, width, target_x, on_done=None):
        if self._sidebar_anim_job:
            try:
                self.after_cancel(self._sidebar_anim_job)
            except Exception:
                pass
            self._sidebar_anim_job = None

        panel = self._sidebar_frame
        if panel is None or not panel.winfo_exists():
            if on_done:
                on_done()
            return

        try:
            current_x = int(float(panel.place_info().get("x", 0)))
        except Exception:
            current_x = -width
        steps = _SIDEBAR_STEPS
        delta = (target_x - current_x) / steps

        def _step(i, x):
            if panel is None or not panel.winfo_exists():
                self._sidebar_anim_job = None
                if on_done:
                    on_done()
                return
            nx = target_x if i >= steps else int(x + delta)
            try:
                panel.place_configure(x=nx)
            except Exception:
                pass
            if i >= steps:
                self._sidebar_anim_job = None
                if on_done:
                    on_done()
            else:
                self._sidebar_anim_job = self.after(_SIDEBAR_STEP_MS, _step, i + 1, nx)

        _step(1, current_x)

    def _on_root_resize_sidebar(self, _event=None):
        if self._sidebar_dim is not None and self._sidebar_dim.winfo_exists():
            self._sidebar_dim.place_configure(width=self.winfo_width(), height=self.winfo_height())
        if self._sidebar_frame is not None and self._sidebar_frame.winfo_exists():
            self._sidebar_frame.place_configure(height=self.winfo_height())

    # Content

    def _build_sidebar_content(self, panel):
        header = tk.Frame(panel, bg=SURFACE())
        header.pack(fill="x", padx=self._s(16), pady=(self._s(16), self._s(8)))
        tk.Label(header, text=t("menu"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(side="left")
        tk.Button(
            header, text="\u2715", font=(FONT_MONO, self._fs(10)),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2", command=self._close_sidebar,
        ).pack(side="right")

        tk.Frame(panel, bg=BORDER(), height=1).pack(fill="x", padx=self._s(16), pady=(0, self._s(8)))

        self._sidebar_menu_item(panel, t("language"), self._open_language_from_sidebar)
        self._sidebar_menu_item(panel, t("settings"), self._open_settings_from_sidebar)

        tk.Frame(panel, bg=BORDER(), height=1).pack(fill="x", padx=self._s(16), pady=(self._s(8), self._s(8)))

        theme_row = tk.Frame(panel, bg=SURFACE())
        theme_row.pack(fill="x", padx=self._s(16), pady=(0, self._s(4)))
        tk.Label(theme_row, text=t("theme"), font=(FONT_MONO, self._fs(9)),
                 fg=FG2(), bg=SURFACE()).pack(side="left")
        theme_toggle = tk.Button(
            theme_row, text="\u2600" if self._dark_mode else "\u263e",
            font=(FONT_MONO, self._fs(10)),
            fg=FG(), bg=SURFACE2(), activebackground=SURFACE2(), activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2", padx=self._s(8), pady=self._s(3),
            command=self._toggle_theme_from_sidebar,
        )
        theme_toggle.pack(side="right")
        self._sidebar_theme_toggle_btn = theme_toggle

        # Footer, anchored to the bottom of the panel regardless of content above
        footer = tk.Frame(panel, bg=SURFACE())
        footer.place(relx=0.0, rely=1.0, anchor="sw", x=self._s(16), y=-self._s(14))
        tk.Label(footer, text=self._name_var.get() or socket.gethostname(),
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=SURFACE()).pack(anchor="w")
        tk.Label(footer, text=f"V{VERSION}",
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=SURFACE()).pack(anchor="w")

    def _sidebar_menu_item(self, panel, label, command):
        btn = tk.Button(
            panel, text=label, font=(FONT_MONO, self._fs(10)),
            fg=FG(), bg=SURFACE(), activebackground=SURFACE2(), activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2", anchor="w",
            padx=self._s(12), pady=self._s(10),
            command=command,
        )
        btn.pack(fill="x", padx=self._s(4))
        self._add_hover(btn, SURFACE(), SURFACE2())

    # Item actions -- close the drawer first, then open the destination once
    # the close animation has had time to finish (avoids two overlapping
    # Toplevels/animations fighting for the same screen space)

    def _open_language_from_sidebar(self):
        self._close_sidebar()
        self.after(_SIDEBAR_STEPS * _SIDEBAR_STEP_MS + 30, self._open_language_modal)

    def _open_settings_from_sidebar(self):
        self._close_sidebar()
        self.after(_SIDEBAR_STEPS * _SIDEBAR_STEP_MS + 30, self._open_settings_modal)

    def _toggle_theme_from_sidebar(self):
        self._toggle_theme()
        if self._sidebar_theme_toggle_btn is not None and self._sidebar_theme_toggle_btn.winfo_exists():
            self._sidebar_theme_toggle_btn.configure(text="\u2600" if self._dark_mode else "\u263e")
