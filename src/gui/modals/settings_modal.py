"""
Settings modal -- internal-sidebar layout (confirmed option "b" from the
clarification round): a narrow vertical nav on the left inside the modal,
content pane on the right, 7 sections: Premium / Cloud / Tunnel / Sharing /
Permissions / Updates / About.

Built on top of ModalMixin._show_modal() (base_modal.py) -- same opaque
backdrop + centered window as the Languages modal, so the pattern validated
there carries over unchanged.
"""

import tkinter as tk

from src.constants import FONT_MONO
from src.i18n import t
from src.theme import SURFACE, SURFACE2, BORDER, FG, FG2, FG3


_SECTIONS = [
    ("premium",     "premium",     "_settings_section_premium"),
    ("cloud",       "cloud",       "_settings_section_cloud"),
    ("tunnel",      "tunnel",      "_settings_section_tunnel"),
    ("sharing",     "sharing",     "_settings_section_sharing"),
    ("permissions", "permissions", "_settings_section_permissions"),
    ("history",     "history",     "_settings_section_history"),
    ("updates",     "updates",     "_settings_section_updates"),
    ("about",       "about",       "_settings_section_about"),
]


class SettingsModalMixin:

    _settings_active_key = "premium"
    _settings_nav_buttons: dict | None = None
    _settings_content_frame: tk.Frame | None = None

    def _open_settings_modal(self):
        self._show_modal(t("settings"), self._build_settings_modal_content, width=560, height=440)
        self._settings_premium_signature = None
        self._settings_poll_generation = getattr(self, "_settings_poll_generation", 0) + 1
        generation = self._settings_poll_generation
        self.after(750, lambda: self._poll_premium_table(generation))

    def _poll_premium_table(self, generation):
        """Refresh an open Premium table when a phone redeems a code."""
        if generation != getattr(self, "_settings_poll_generation", None):
            return
        content = self._settings_content_frame
        if content is None or not content.winfo_exists():
            return
        if self._settings_active_key == "premium":
            from src.core import unlock_codes
            codes = unlock_codes.list_codes()
            signature = tuple(
                (code["id"], code.get("device_id"), code.get("redeemed_at"), code["revoked"])
                for code in codes
            )
            if self._settings_premium_signature is None:
                self._settings_premium_signature = signature
            elif signature != self._settings_premium_signature:
                self._settings_premium_signature = signature
                self._render_settings_active_section()
        self.after(750, lambda: self._poll_premium_table(generation))

    def _build_settings_modal_content(self, parent, close_fn):
        parent.pack_propagate(False)

        modal_width = max(1, parent.master.winfo_width())
        nav_width = self._s(96 if modal_width < self._s(520) else 120)
        nav = tk.Frame(parent, bg=SURFACE(), width=nav_width)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)

        tk.Frame(parent, bg=BORDER(), width=1).pack(side="left", fill="y")

        content = tk.Frame(parent, bg=SURFACE())
        content.pack(side="left", fill="both", expand=True, padx=(self._s(14), 0))
        self._settings_content_frame = content

        self._settings_nav_buttons = {}
        for key, label_key, _builder in _SECTIONS:
            btn = tk.Button(
                nav, text=t(label_key), font=(FONT_MONO, self._fs(8)),
                fg=FG() if key == self._settings_active_key else FG2(),
                bg=SURFACE2() if key == self._settings_active_key else SURFACE(),
                activebackground=SURFACE2(), activeforeground=FG(),
                relief="flat", bd=0, cursor="hand2", anchor="w",
                padx=self._s(6 if nav_width < self._s(110) else 10), pady=self._s(8),
                command=lambda k=key: self._switch_settings_section(k),
            )
            btn.pack(fill="x", pady=(0, self._s(1)))
            self._settings_nav_buttons[key] = btn

        self._settings_refresh_active_section = self._render_settings_active_section
        self._render_settings_active_section()

    def _switch_settings_section(self, key: str):
        self._settings_active_key = key
        for k, btn in (self._settings_nav_buttons or {}).items():
            if not btn.winfo_exists():
                continue
            btn.configure(
                fg=FG() if k == key else FG2(),
                bg=SURFACE2() if k == key else SURFACE(),
            )
        self._render_settings_active_section()

    def _render_settings_active_section(self):
        content = self._settings_content_frame
        if content is None or not content.winfo_exists():
            return
        for w in content.winfo_children():
            w.destroy()

        # Scrollable body -- some sections (Sharing, Premium with many
        # folders) can outgrow the fixed modal height.
        canvas = tk.Canvas(content, bg=SURFACE(), highlightthickness=0)
        scrollbar = tk.Scrollbar(content, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        body = tk.Frame(canvas, bg=SURFACE())
        window_id = canvas.create_window((0, 0), window=body, anchor="nw")

        def _on_configure(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(window_id, width=canvas.winfo_width())
        body.bind("<Configure>", _on_configure)
        canvas.bind("<Configure>", _on_configure)

        def _on_mousewheel(event):
            if not canvas.winfo_exists():
                return
            step = -1 * (event.delta // 120 or (1 if event.delta > 0 else -1))
            canvas.yview_scroll(step, "units")
        modal_toplevel = canvas.winfo_toplevel()
        modal_toplevel.bind("<MouseWheel>", _on_mousewheel)

        builder_name = next(b for k, _l, b in _SECTIONS if k == self._settings_active_key)
        builder = getattr(self, builder_name)
        builder(body)
