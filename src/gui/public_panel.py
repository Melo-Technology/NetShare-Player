"""PublicPanelMixin extracted from the main GUI window."""

from pathlib import Path
import secrets
from tkinter import messagebox

import tkinter as tk

import src.state as state
from src.constants import FONT_MONO
from src.deps import HAS_QRCODE
from src.i18n import t
from src.theme import _theme, BG, SURFACE, BORDER, FG, FG2, FG3, DANGER


class PublicPanelMixin:

    def _new_public_key(self) -> str:
        return secrets.token_urlsafe(18)

    def _rotate_public_keys(self):
        self._community_key_var.set(self._new_public_key())
        self._admin_key_var.set(self._new_public_key())

    def _sync_public_config_from_vars(self):
        state.COMMUNITY_PASSWORD = self._community_key_var.get().strip()
        state.ADMIN_PASSWORD = self._admin_key_var.get().strip()
        state.COMMUNITY_BROWSE_ROOT = bool(self._community_browse_root_var.get())
        state.COMMUNITY_DOWNLOAD = bool(self._community_download_var.get())
        state.COMMUNITY_UPLOAD = bool(self._community_upload_var.get())
        state.PUBLIC_UPLOAD_MODE = self._public_upload_mode_var.get()
        state.MAX_UPLOADS_PER_HOUR = max(1, int(self._max_uploads_var.get()))
        state.MAX_UPLOAD_SIZE_MB = max(1, int(self._max_size_var.get()))
        state.ALLOWED_UPLOAD_EXTENSIONS = self._selected_upload_extensions()
        state.save_public_config()
        if getattr(self, "_tunnel_active", False) and getattr(self, "_tunnel_url", ""):
            self._draw_public_active(self._tunnel_url)

    def _draw_public_offline_placeholder(self):
        for w in self._public_section.winfo_children():
            w.destroy()
        self._responsive_wrap(tk.Label(self._public_section,
                 text=t("public_placeholder"),
                 font=(FONT_MONO, self._fs(9)), fg=FG3(), bg=BG()), padding=72).pack(anchor="w", fill="x")
        self._build_public_config_controls(self._public_section)


    def _draw_public_ready(self):
        for w in self._public_section.winfo_children():
            w.destroy()
        self._responsive_wrap(tk.Label(self._public_section,
                 text=t("public_ready"),
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=BG()
                 ), padding=72).pack(anchor="w", fill="x", pady=(0, self._s(8)))
        self._build_public_config_controls(self._public_section)
        self._public_btn = tk.Button(
            self._public_section, text=t("share_publicly"),
            font=(FONT_MONO, self._fs(10), "bold"),
            fg=BG(), bg=FG(),
            activebackground=FG2(), activeforeground=BG(),
            relief="flat", bd=0, cursor="hand2", pady=self._s(12),
            command=self._start_tunnel,
        )
        self._public_btn.pack(fill="x")
        self._add_hover(self._public_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())


    def _build_public_config_controls(self, parent):
        outer = tk.Frame(parent, bg=SURFACE(), highlightthickness=1, highlightbackground=BORDER())
        outer.pack(fill="x", pady=(self._s(8), self._s(8)))

        def _entry_row(label, var, show=""):
            row = tk.Frame(outer, bg=SURFACE())
            row.pack(fill="x", padx=self._s(10), pady=(self._s(8), 0))
            tk.Label(row, text=label, font=(FONT_MONO, self._fs(8)),
                    fg=FG3(), bg=SURFACE(), width=16, anchor="w").pack(side="left")
            entry = tk.Entry(row, textvariable=var, show=show,
                            font=(FONT_MONO, self._fs(8)), fg=FG(), bg=BG(),
                            insertbackground=FG(), relief="flat", bd=0,
                            highlightthickness=1, highlightbackground=BORDER())
            entry.pack(side="left", fill="x", expand=True, ipady=self._s(5))
            tk.Button(row, text=t("generate"), font=(FONT_MONO, self._fs(7)),
                    fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                    relief="flat", bd=0, cursor="hand2",
                    command=lambda v=var: (v.set(self._new_public_key()), self._sync_public_config_from_vars())
                    ).pack(side="right", padx=(self._s(6), 0))

        _entry_row(t("community_key"), self._community_key_var, "-")
        _entry_row(t("admin_key"), self._admin_key_var, "-")


        community_row = tk.Frame(outer, bg=SURFACE())
        community_row.pack(fill="x", padx=self._s(10), pady=(self._s(8), 0))
        tk.Label(
            community_row,
            text=t("community"),
            font=(FONT_MONO, self._fs(8)),
            fg=FG3(), bg=SURFACE(), width=16, anchor="w",
        ).pack(anchor="w")
        community_options = tk.Frame(community_row, bg=SURFACE())
        community_options.pack(fill="x", pady=(self._s(2), 0))
        for label, var in (
            (t("root_browser"), self._community_browse_root_var),
            (t("download"), self._community_download_var),
            (t("upload"), self._community_upload_var),
        ):
            cb = tk.Checkbutton(
                community_options,
                text=label,
                variable=var,
                command=self._sync_public_config_from_vars,
                font=(FONT_MONO, self._fs(7)),
                fg=FG2(), bg=SURFACE(),
                activeforeground=FG(), activebackground=SURFACE(),
                selectcolor=BG(),
                relief="flat", bd=0, cursor="hand2",
                highlightthickness=0,
                anchor="w",
            )
            self._responsive_wrap(cb, padding=96)
            cb.pack(anchor="w", fill="x")

        mode_row = tk.Frame(outer, bg=SURFACE())
        mode_row.pack(fill="x", padx=self._s(10), pady=(self._s(8), 0))
        tk.Label(mode_row, text=t("receive_mode"), font=(FONT_MONO, self._fs(8)),
                fg=FG3(), bg=SURFACE(), anchor="w").pack(anchor="w")
        mode_options = tk.Frame(mode_row, bg=SURFACE())
        mode_options.pack(fill="x", pady=(self._s(2), 0))
        for label, value in ((t("direct_accept"), "direct"), (t("ask_first"), "request")):
            rb = tk.Radiobutton(
                mode_options,
                text=label,
                value=value,
                variable=self._public_upload_mode_var,
                command=self._sync_public_config_from_vars,
                font=(FONT_MONO, self._fs(7)),
                fg=FG2(), bg=SURFACE(),
                activeforeground=FG(), activebackground=SURFACE(),
                selectcolor=BG(),
                relief="flat", bd=0, cursor="hand2",
                highlightthickness=0,
                anchor="w",
            )
            self._responsive_wrap(rb, padding=96)
            rb.pack(anchor="w", fill="x")

        # Only show upload controls if upload is enabled remotely
        upload_enabled = self._remote_flags.get("upload")
        if upload_enabled is None or upload_enabled:
            for label, var, frm, to in (
                (t("uploads_per_hour"), self._max_uploads_var, 1, 100),
                (t("max_size_mb"),  self._max_size_var,    1, 500),
            ):
                row = tk.Frame(outer, bg=SURFACE())
                row.pack(fill="x", padx=self._s(10), pady=(self._s(8), 0))
                tk.Label(row, text=label, font=(FONT_MONO, self._fs(8)),
                        fg=FG3(), bg=SURFACE(), width=16, anchor="w").pack(side="left")
                tk.Scale(row, from_=frm, to=to, orient="horizontal", variable=var,
                        command=lambda _value: self._sync_public_config_from_vars(),
                        bg=SURFACE(), fg=FG2(), troughcolor=BG(),
                        highlightthickness=0, relief="flat").pack(side="left", fill="x", expand=True)

            types = tk.Frame(outer, bg=SURFACE())
            types.pack(fill="x", padx=self._s(10), pady=self._s(8))
            tk.Label(types, text=t("allowed_types"), font=(FONT_MONO, self._fs(8)),
                    fg=FG3(), bg=SURFACE(), anchor="w").pack(anchor="w")
            type_options = tk.Frame(types, bg=SURFACE())
            type_options.pack(fill="x", pady=(self._s(2), 0))
            for label, var in self._upload_type_vars.items():
                cb = tk.Checkbutton(
                    type_options,
                    text=label,
                    variable=var,
                    command=self._sync_public_config_from_vars,
                    font=(FONT_MONO, self._fs(7)),
                    fg=FG2(), bg=SURFACE(),
                    activeforeground=FG(), activebackground=SURFACE(),
                    selectcolor=BG(),
                    relief="flat", bd=0, cursor="hand2",
                    highlightthickness=0,
                    anchor="w",
                )
                self._responsive_wrap(cb, padding=96)
                cb.pack(anchor="w", fill="x")

        # Show a notice when upload is remotely disabled
        else:
            notice_row = tk.Frame(outer, bg=SURFACE())
            notice_row.pack(fill="x", padx=self._s(10), pady=self._s(8))
            self._responsive_wrap(tk.Label(
                notice_row,
                text=t("upload_disabled_remotely"),
                font=(FONT_MONO, self._fs(7)),
                fg=FG3(), bg=SURFACE(),
            ), padding=96).pack(anchor="w", fill="x")


    def _selected_upload_extensions(self) -> set[str]:
        groups = {
            "images": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic"},
            "video": {".mp4", ".mov", ".mkv", ".avi", ".webm"},
            "audio": {".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg"},
            "documents": {".txt", ".md", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"},
            "archives": {".zip", ".rar", ".7z", ".tar", ".gz"},
        }
        selected: set[str] = set()
        for name, extensions in groups.items():
            if self._upload_type_vars[name].get():
                selected.update(extensions)
        return selected


    def _draw_public_connecting(self):
        for w in self._public_section.winfo_children():
            w.destroy()
        self._responsive_wrap(tk.Label(self._public_section, text=f"*  {t('connecting')}",
                 font=(FONT_MONO, self._fs(9)), fg=FG2(), bg=BG()), padding=72).pack(anchor="w", fill="x")


    def _draw_public_reconnecting(self, delay: int, attempt: int):
        for w in self._public_section.winfo_children():
            w.destroy()
        self._responsive_wrap(tk.Label(self._public_section,
                 text=f"*  {t('reconnecting', delay=delay, attempt=attempt)}",
                 font=(FONT_MONO, self._fs(9)), fg=FG2(), bg=BG()), padding=72).pack(anchor="w", fill="x")
        tk.Button(
            self._public_section, text=t("stop"),
            font=(FONT_MONO, self._fs(8)),
            fg=FG(), bg=DANGER(),
            activebackground="#991111", activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2",
            padx=self._s(14), pady=self._s(6),
            command=self._stop_tunnel,
        ).pack(anchor="w", pady=(self._s(6), 0))


    def _draw_public_active(self, url: str):
        for w in self._public_section.winfo_children():
            w.destroy()

        badge_row = tk.Frame(self._public_section, bg=BG())
        badge_row.pack(fill="x", pady=(0, self._s(4)))
        dot_size = self._s(8)
        dot_cv = tk.Canvas(badge_row, width=dot_size, height=dot_size,
                           bg=BG(), highlightthickness=0)
        dot_cv.pack(side="left", padx=(0, self._s(6)))
        dot_cv.create_oval(0, 0, dot_size, dot_size, fill="#22cc44", outline="")
        tk.Label(badge_row, text=t("live"),
                 font=(FONT_MONO, self._fs(8)), fg=FG2(), bg=BG()).pack(side="left")

        url_box = tk.Frame(
            self._public_section,
            bg=SURFACE(),
            highlightthickness=1,
            highlightbackground=BORDER(),
        )
        url_box.pack(fill="x", pady=(0, self._s(8)))
        tk.Label(url_box, text=t("public_url"),
                 font=(FONT_MONO, self._fs(8), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", padx=self._s(10), pady=(self._s(8), 0))

        url_row = tk.Frame(url_box, bg=SURFACE())
        url_row.pack(fill="x", padx=self._s(10), pady=(self._s(4), self._s(8)))
        url_lbl = tk.Label(url_row, text=url,
                           font=(FONT_MONO, self._fs(9), "bold"),
                           fg=FG(), bg=SURFACE(), cursor="hand2", anchor="w")
        url_lbl.pack(side="left", fill="x", expand=True)
        url_lbl.bind("<Button-1>", lambda e: self._copy(url))
        if HAS_QRCODE:
            tk.Button(url_row, text="QR", font=(FONT_MONO, self._fs(8)),
                      fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                      relief="flat", bd=0, cursor="hand2", padx=self._s(8),
                      command=lambda: self._show_qr(url)).pack(side="right")
        tk.Button(url_row, text=t("copy"), font=(FONT_MONO, self._fs(8)),
                  fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                  relief="flat", bd=0, cursor="hand2", padx=self._s(8),
                  command=lambda: self._copy(url)).pack(side="right")

        self._responsive_wrap(tk.Label(
            self._public_section,
            text=t("public_url_password_hint"),
            font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=BG(),
        ), padding=72).pack(anchor="w", fill="x", pady=(0, self._s(6)))

        live_rights = tk.Frame(
            self._public_section,
            bg=SURFACE(),
            highlightthickness=1,
            highlightbackground=BORDER(),
        )
        live_rights.pack(fill="x", pady=(0, self._s(8)))
        tk.Label(
            live_rights,
            text=t("community_privileges"),
            font=(FONT_MONO, self._fs(8), "bold"),
            fg=FG3(), bg=SURFACE(),
        ).pack(anchor="w", padx=self._s(10), pady=(self._s(8), 0))
        live_rights_row = tk.Frame(live_rights, bg=SURFACE())
        live_rights_row.pack(fill="x", padx=self._s(10), pady=self._s(8))
        for label, var in (
            (t("root_browser"), self._community_browse_root_var),
            (t("download"), self._community_download_var),
            (t("upload"), self._community_upload_var),
        ):
            cb = tk.Checkbutton(
                live_rights_row,
                text=label,
                variable=var,
                command=self._sync_public_config_from_vars,
                font=(FONT_MONO, self._fs(7)),
                fg=FG2(), bg=SURFACE(),
                activeforeground=FG(), activebackground=SURFACE(),
                selectcolor=BG(),
                relief="flat", bd=0, cursor="hand2",
                highlightthickness=0,
                anchor="w",
            )
            self._responsive_wrap(cb, padding=96)
            cb.pack(anchor="w", fill="x")

        self._draw_public_access_key(
            t("admin_key_title"),
            state.ADMIN_PASSWORD,
            t("admin_key_description"),
        )
        community_rights = [
            t("browse_root") if state.COMMUNITY_BROWSE_ROOT else t("incoming_only"),
            t("download") if state.COMMUNITY_DOWNLOAD else t("no_download"),
            t("upload") if state.COMMUNITY_UPLOAD else t("no_upload"),
        ]
        self._draw_public_access_key(
            t("community_key_title"),
            state.COMMUNITY_PASSWORD,
            t("community_key_description", rights=", ".join(community_rights)),
        )

        local_pw_hint = self._password_var.get().strip()
        tk.Label(self._public_section,
                 text=t(
                     "local_pw_unchanged",
                     status=t("set") if local_pw_hint else t("none"),
                 ),
                 font=(FONT_MONO, self._fs(7)), fg=FG3(), bg=BG()
                 ).pack(anchor="w", pady=(0, self._s(6)))

        tk.Button(self._public_section, text=t("stop_sharing"),
                  font=(FONT_MONO, self._fs(9), "bold"),
                  fg=FG(), bg=DANGER(),
                  activebackground="#991111", activeforeground=FG(),
                  relief="flat", bd=0, cursor="hand2", pady=self._s(10),
                  command=self._stop_tunnel
                  ).pack(fill="x", pady=(self._s(4), 0))


    def _draw_public_error(self, msg: str):
        for w in self._public_section.winfo_children():
            w.destroy()
        tk.Label(self._public_section, text=f"✕  {msg}",
                 font=(FONT_MONO, self._fs(8)), fg=DANGER(), bg=BG(),
                 wraplength=self._win_w - self._s(60), justify="left"
                 ).pack(anchor="w", pady=(0, self._s(8)))
        retry_btn = tk.Button(
            self._public_section, text=t("retry"),
            font=(FONT_MONO, self._fs(9), "bold"),
            fg=BG(), bg=FG(),
            activebackground=FG2(), activeforeground=BG(),
            relief="flat", bd=0, cursor="hand2", pady=self._s(10),
            command=self._start_tunnel,
        )
        retry_btn.pack(fill="x")
        self._add_hover(retry_btn, FG(), FG2(), text_normal=BG(), text_hover=BG())

    # QR code popup

    def _show_qr(self, url: str):
        try:
            import qrcode as _qr
            from PIL import ImageTk, Image as _PilImg, ImageDraw
        except ImportError:
            messagebox.showinfo(t("qr_code_title"), t("qr_install"))
            return

        QR_SIZE   = 260
        LOGO_FRAC = 0.22
        ico_path  = Path(__file__).parent.parent.parent / "favicon.ico"

        qr = _qr.QRCode(error_correction=_qr.constants.ERROR_CORRECT_H, box_size=10, border=4)
        qr.add_data(url); qr.make(fit=True)

        is_dark = _theme.get("BG", "#000") in ("#000000", "#0f0f0f", "#1a1a1a")
        qr_fg   = "#ffffff" if is_dark else "#0a0a0a"
        qr_bg   = "#000000" if is_dark else "#ffffff"

        img_pil  = qr.make_image(fill_color=qr_fg, back_color=qr_bg).convert("RGBA")
        img_pil  = img_pil.resize((QR_SIZE, QR_SIZE), _PilImg.LANCZOS)
        logo_px  = int(QR_SIZE * LOGO_FRAC)
        logo_img = None

        if ico_path.exists():
            try:
                raw     = _PilImg.open(ico_path).convert("RGBA")
                bg_img  = _PilImg.new("RGBA", (logo_px, logo_px), (0, 0, 0, 0))
                draw_bg = ImageDraw.Draw(bg_img)
                draw_bg.rounded_rectangle(
                    [0, 0, logo_px-1, logo_px-1], radius=logo_px//5,
                    fill=qr_bg+"ff" if len(qr_bg)==7 else qr_bg,
                )
                inner  = int(logo_px * 0.72)
                raw    = raw.resize((inner, inner), _PilImg.LANCZOS)
                offset = (logo_px - inner) // 2
                bg_img.paste(raw, (offset, offset), mask=raw)
                logo_img = bg_img
            except Exception:
                logo_img = None

        if logo_img is None:
            from PIL import ImageFont
            logo_img = _PilImg.new("RGBA", (logo_px, logo_px), (0, 0, 0, 0))
            draw     = ImageDraw.Draw(logo_img)
            draw.rounded_rectangle([0, 0, logo_px-1, logo_px-1], radius=logo_px//5, fill=qr_fg)
            font_size = max(10, logo_px // 2); fnt = None
            for fp in [
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
                "/System/Library/Fonts/Courier.ttc",
                "C:/Windows/Fonts/cour.ttf",
            ]:
                try:
                    fnt = ImageFont.truetype(fp, font_size); break
                except Exception:
                    pass
            if fnt is None:
                fnt = ImageFont.load_default()
            bbox = draw.textbbox((0, 0), "NS", font=fnt)
            draw.text(
                ((logo_px-(bbox[2]-bbox[0]))//2-bbox[0],
                 (logo_px-(bbox[3]-bbox[1]))//2-bbox[1]),
                "NS", font=fnt, fill=qr_bg,
            )

        img_pil.paste(logo_img, ((QR_SIZE-logo_px)//2, (QR_SIZE-logo_px)//2), mask=logo_img)
        img_tk = ImageTk.PhotoImage(img_pil)

        win = tk.Toplevel(self)
        win.title(t("qr_title"))
        win.configure(bg=BG())
        win.resizable(False, False)
        if ico_path.exists():
            try:
                win.iconbitmap(str(ico_path))
            except Exception:
                pass
        frame = tk.Frame(win, bg=FG(), padx=self._s(16), pady=self._s(16))
        frame.pack(padx=self._s(24), pady=(self._s(24), self._s(12)))
        tk.Label(frame, image=img_tk, bg=FG()).pack()
        win._img_ref = img_tk
        tk.Label(win, text=url, font=(FONT_MONO, self._fs(9)),
                 fg=FG3(), bg=BG()).pack(pady=(0, self._s(16)))

    # Log helpers

