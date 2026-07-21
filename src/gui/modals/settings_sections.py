"""
Content builders for each Settings modal section.

Reuse policy followed throughout this file: where an existing mixin method
already builds the right widgets bound to the right Tk variables and calls
the right handlers (e.g. PublicPanelMixin._build_public_config_controls,
which is already parameterized by `parent`), this file calls that method
directly instead of re-implementing it -- avoids a second source of truth
for the same state. Where the existing equivalent is hardwired to a fixed
frame on the main page (e.g. the OTP pairing ring in pairing_panel.py), this
file builds a simplified, self-contained equivalent bound to the same
underlying `state` functions, rather than fighting that wiring -- flagged
inline where it trades away visual polish (the countdown ring) for being
safe to embed anywhere.
"""

import threading
from pathlib import Path
from tkinter import filedialog, simpledialog, messagebox

import tkinter as tk

import src.state as state
from src.constants import FONT_MONO, VERSION
from src.i18n import t
from src.theme import BG, SURFACE, SURFACE2, BORDER, FG, FG2, FG3, DANGER


class SettingsSectionsMixin:

    def _settings_dialog_parent(self):
        return self._modal_overlay if getattr(self, "_modal_overlay", None) else self

    # Premium (Feature 1)

    def _settings_section_premium(self, parent):
        from src.core import unlock_codes

        tk.Label(parent, text=t("premium_folders"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(6)))

        folders = unlock_codes.list_premium_folders()
        if not folders:
            tk.Label(parent, text=t("no_premium_folders"), font=(FONT_MONO, self._fs(8)),
                     fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(10)))
        else:
            for info in folders:
                self._settings_premium_folder_row(parent, info)

        tk.Button(
            parent, text=t("mark_folder_premium"), font=(FONT_MONO, self._fs(8), "bold"),
            fg=FG(), bg=SURFACE2(), activebackground=FG(), activeforeground=BG(),
            relief="flat", bd=0, cursor="hand2", padx=self._s(10), pady=self._s(8),
            command=self._prompt_mark_folder_premium,
        ).pack(anchor="w", pady=(self._s(4), 0))

        self._settings_premium_codes_table(parent, unlock_codes.list_codes())

    def _settings_premium_folder_row(self, parent, info):
        row = tk.Frame(parent, bg=SURFACE(), highlightthickness=1, highlightbackground=BORDER())
        row.pack(fill="x", pady=(0, self._s(6)))

        top = tk.Frame(row, bg=SURFACE())
        top.pack(fill="x", padx=self._s(10), pady=(self._s(8), 0))
        tk.Label(top, text=f"{info['label']}   {info['folder_path']}",
                 font=(FONT_MONO, self._fs(8), "bold"), fg=FG(), bg=SURFACE()
                 ).pack(side="left", fill="x", expand=True, anchor="w")
        if info.get("price_note"):
            tk.Label(top, text=info["price_note"], font=(FONT_MONO, self._fs(7)),
                     fg=FG3(), bg=SURFACE()).pack(side="right")

        btn_row = tk.Frame(row, bg=SURFACE())
        btn_row.pack(fill="x", padx=self._s(10), pady=(self._s(4), self._s(8)))
        tk.Button(
            btn_row, text=t("generate_code"), font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            command=lambda p=info["folder_path"]: self._generate_premium_code(p),
        ).pack(side="left")

    def _settings_premium_codes_table(self, parent, codes):
        tk.Label(parent, text=t("codes_table"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(self._s(18), self._s(6)))

        if not codes:
            tk.Label(parent, text=t("no_active_codes"), font=(FONT_MONO, self._fs(8)),
                     fg=FG3(), bg=SURFACE()).pack(anchor="w")
            return

        table = tk.Frame(parent, bg=SURFACE(), highlightthickness=1,
                         highlightbackground=BORDER())
        table.pack(fill="x")
        columns = (
            ("code_number", 0, 0),
            ("code_status", 1, 1),
            ("redeemed_device", 2, 2),
            ("code_folder", 3, 2),
            ("code_action", 4, 0),
        )
        for key, column, weight in columns:
            table.grid_columnconfigure(column, weight=weight)
            tk.Label(table, text=t(key), font=(FONT_MONO, self._fs(7), "bold"),
                     fg=FG3(), bg=SURFACE2(), padx=self._s(7), pady=self._s(6),
                     anchor="w").grid(row=0, column=column, sticky="nsew")

        for grid_row, code in enumerate(codes, start=1):
            self._settings_code_table_row(table, grid_row, code)

    @staticmethod
    def _truncate_premium_folder(path, limit=28):
        path = str(path)
        return path if len(path) <= limit else path[:limit - 3] + "..."

    def _settings_code_table_row(self, table, grid_row, c):
        if c["revoked"]:
            status = t("code_revoked")
        elif c["expired"]:
            status = t("code_expired")
        elif c["used"]:
            status = t("code_redeemed")
        else:
            status = t("code_unused")

        values = (
            f"#{c['id']}",
            status,
            c.get("device_id") or "",
            self._truncate_premium_folder(c["folder_path"]),
        )
        for column, value in enumerate(values):
            tk.Label(table, text=value, font=(FONT_MONO, self._fs(7)), fg=FG2(),
                     bg=SURFACE(), padx=self._s(7), pady=self._s(5), anchor="w"
                     ).grid(row=grid_row, column=column, sticky="nsew")

        if not c["revoked"]:
            tk.Button(
                table, text=t("revoke"), font=(FONT_MONO, self._fs(7)),
                fg=DANGER(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                relief="flat", bd=0, cursor="hand2", padx=self._s(7),
                command=lambda cid=c["id"]: self._revoke_premium_code(cid),
            ).grid(row=grid_row, column=4, sticky="w")

    def _prompt_mark_folder_premium(self):
        root_dir = state.ROOT_DIR
        if not root_dir or not Path(root_dir).exists():
            messagebox.showwarning(t("netshare_title"), t("no_folder"))
            return
        chosen = filedialog.askdirectory(initialdir=str(root_dir), title=t("mark_folder_premium"))
        if not chosen:
            return
        try:
            rel = "/" + str(Path(chosen).resolve().relative_to(Path(root_dir).resolve())).replace("\\", "/")
        except ValueError:
            messagebox.showwarning(t("netshare_title"), t("mark_folder_premium"))
            return
        parent = self._settings_dialog_parent()
        label = simpledialog.askstring(t("premium_folder_label_prompt"), t("premium_folder_label_prompt"), parent=parent)
        if not label:
            return
        price_note = simpledialog.askstring(
            t("premium_folder_price_prompt"), t("premium_folder_price_prompt"), parent=parent
        ) or ""
        from src.core import unlock_codes
        if unlock_codes.mark_premium_folder(rel, label, price_note):
            self._log(f"PREMIUM marked {rel}", "ok")
        self._settings_refresh_active_section()

    def _generate_premium_code(self, folder_path: str):
        from src.core import unlock_codes
        result = unlock_codes.generate_code(folder_path)
        if result:
            self._copy(result["code"])
            self._log(f"PREMIUM code generated for {folder_path} (copied to clipboard)", "ok")
        self._settings_refresh_active_section()

    def _revoke_premium_code(self, code_id: int):
        from src.core import unlock_codes
        unlock_codes.revoke_code(code_id)
        self._log(f"PREMIUM code #{code_id} revoked", "dim")
        self._settings_refresh_active_section()

    # Cloud (Feature 2)

    def _settings_section_cloud(self, parent):
        from src.core.cloud import get_manager
        from src.core.cloud import mega as mega_mod
        from src.deps import HAS_REQUESTS

        tk.Label(parent, text=t("cloud_accounts"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(6)))

        accounts = get_manager().connected_accounts()
        if not accounts:
            tk.Label(parent, text=t("no_cloud_accounts"), font=(FONT_MONO, self._fs(8)),
                     fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(10)))
        else:
            for acc in accounts:
                row = tk.Frame(parent, bg=SURFACE(), highlightthickness=1, highlightbackground=BORDER())
                row.pack(fill="x", pady=(0, self._s(6)))
                inner = tk.Frame(row, bg=SURFACE())
                inner.pack(fill="x", padx=self._s(10), pady=self._s(8))
                tk.Label(
                    inner, text=f"{acc['provider_id'].upper()}   {acc['label']}",
                    font=(FONT_MONO, self._fs(8)), fg=FG2(), bg=SURFACE()
                ).pack(side="left", fill="x", expand=True, anchor="w")
                tk.Button(
                    inner, text=t("disconnect"), font=(FONT_MONO, self._fs(7)),
                    fg=DANGER(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                    relief="flat", bd=0, cursor="hand2",
                    command=lambda p=acc["provider_id"], a=acc["account_id"]: self._disconnect_cloud_account(p, a),
                ).pack(side="right")

        tk.Frame(parent, bg=BORDER(), height=1).pack(fill="x", pady=self._s(10))

        # Google Drive
        drive_row = tk.Frame(parent, bg=SURFACE())
        drive_row.pack(fill="x", pady=(0, self._s(2)))
        tk.Label(drive_row, text=t("google_drive"), font=(FONT_MONO, self._fs(8), "bold"),
                 fg=FG(), bg=SURFACE()).pack(side="left")
        tk.Button(
            drive_row, text=t("connect"), font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            command=self._prompt_connect_drive,
        ).pack(side="right")
        if not HAS_REQUESTS:
            tk.Label(parent, text=t("requests_missing"),
                     font=(FONT_MONO, self._fs(7)), fg=DANGER(), bg=SURFACE()
                     ).pack(anchor="w", pady=(0, self._s(6)))
        else:
            tk.Frame(parent, bg=SURFACE(), height=self._s(6)).pack()

        # Dropbox
        dbx_row = tk.Frame(parent, bg=SURFACE())
        dbx_row.pack(fill="x", pady=(0, self._s(6)))
        tk.Label(dbx_row, text=t("dropbox"), font=(FONT_MONO, self._fs(8), "bold"),
                 fg=FG(), bg=SURFACE()).pack(side="left")
        tk.Button(
            dbx_row, text=t("connect"), font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            command=self._prompt_connect_dropbox,
        ).pack(side="right")

        # Mega -- graceful degradation if megatools isn't installed (validated approach)
        mega_row = tk.Frame(parent, bg=SURFACE())
        mega_row.pack(fill="x", pady=(0, self._s(2)))
        tk.Label(mega_row, text=t("mega"), font=(FONT_MONO, self._fs(8), "bold"),
                 fg=FG(), bg=SURFACE()).pack(side="left")
        if mega_mod.is_available():
            tk.Button(
                mega_row, text=t("connect"), font=(FONT_MONO, self._fs(7)),
                fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                relief="flat", bd=0, cursor="hand2",
                command=self._prompt_connect_mega,
            ).pack(side="right")
        else:
            self._responsive_wrap(tk.Label(
                parent, text=mega_mod.unavailable_message(),
                font=(FONT_MONO, self._fs(7)), fg=DANGER(), bg=SURFACE(),
            ), padding=40).pack(anchor="w", fill="x")
        self._responsive_wrap(tk.Label(
            parent, text=t("mega_bridge_notice"), font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=SURFACE(), justify="left",
        ), padding=40).pack(anchor="w", fill="x", pady=(self._s(6), 0))

    def _prompt_connect_drive(self):
        client_id = simpledialog.askstring(
            t("drive_client_id_prompt"), t("drive_client_id_prompt"), parent=self._settings_dialog_parent()
        )
        if not client_id:
            return
        client_id = client_id.strip()
        self._log("CLOUD connecting Google Drive (browser opening)...", "dim")

        def _worker():
            from src.core.cloud import drive
            from src.core.cloud import get_manager, CloudProviderError
            try:
                token_data = drive.connect(client_id)
            except CloudProviderError as e:
                self.after(0, lambda: messagebox.showerror(t("netshare_title"), str(e)))
                return
            account_id = token_data.get("label") or client_id
            get_manager().register_account("drive", account_id, token_data)
            self.after(0, lambda: self._log(f"CLOUD Drive connected: {account_id}", "ok"))
            self.after(0, self._settings_refresh_active_section)

        threading.Thread(target=_worker, daemon=True, name="drive-connect").start()

    def _prompt_connect_dropbox(self):
        app_key = simpledialog.askstring(
            t("dropbox_app_key_prompt"), t("dropbox_app_key_prompt"), parent=self._settings_dialog_parent()
        )
        if not app_key:
            return
        app_key = app_key.strip()
        self._log("CLOUD connecting Dropbox (browser opening)...", "dim")

        def _worker():
            from src.core.cloud import dropbox
            from src.core.cloud import get_manager, CloudProviderError
            try:
                token_data = dropbox.connect(app_key)
            except CloudProviderError as e:
                self.after(0, lambda: messagebox.showerror(t("netshare_title"), str(e)))
                return
            account_id = token_data.get("label") or app_key
            get_manager().register_account("dropbox", account_id, token_data)
            self.after(0, lambda: self._log(f"CLOUD Dropbox connected: {account_id}", "ok"))
            self.after(0, self._settings_refresh_active_section)

        threading.Thread(target=_worker, daemon=True, name="dropbox-connect").start()

    def _prompt_connect_mega(self):
        parent = self._settings_dialog_parent()
        email = simpledialog.askstring(t("mega_email_prompt"), t("mega_email_prompt"), parent=parent)
        if not email:
            return
        password = simpledialog.askstring(
            t("mega_password_prompt"), t("mega_password_prompt"), parent=parent, show="*"
        )
        if not password:
            return
        email = email.strip()
        self._log("CLOUD connecting Mega...", "dim")

        def _worker():
            from src.core.cloud import mega
            from src.core.cloud import get_manager, CloudProviderError
            try:
                token_data = mega.connect(email, password)
            except CloudProviderError as e:
                self.after(0, lambda: messagebox.showerror(t("netshare_title"), str(e)))
                return
            get_manager().register_account("mega", email, token_data)
            self.after(0, lambda: self._log(f"CLOUD Mega connected: {email}", "ok"))
            self.after(0, self._settings_refresh_active_section)

        threading.Thread(target=_worker, daemon=True, name="mega-connect").start()

    def _disconnect_cloud_account(self, provider_id: str, account_id: str):
        from src.core.cloud import get_manager
        get_manager().disconnect(provider_id, account_id)
        self._log(f"CLOUD disconnected {provider_id}/{account_id}", "dim")
        self._settings_refresh_active_section()

    # Tunnel (SSH tunnel controls + Feature 3 custom domain)

    def _settings_section_tunnel(self, parent):
        tk.Label(parent, text=t("public_sharing"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(6)))

        status_row = tk.Frame(parent, bg=SURFACE())
        status_row.pack(fill="x", pady=(0, self._s(6)))
        status_text = self._tunnel_url if (self._tunnel_active and self._tunnel_url) else (
            "..." if self._tunnel_active else t("offline")
        )
        tk.Label(status_row, text=status_text, font=(FONT_MONO, self._fs(8)),
                 fg=FG2(), bg=SURFACE()).pack(side="left", fill="x", expand=True, anchor="w")
        if self._tunnel_url:
            tk.Button(
                status_row, text=t("copy"), font=(FONT_MONO, self._fs(7)),
                fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                relief="flat", bd=0, cursor="hand2",
                command=lambda: self._copy(self._tunnel_url),
            ).pack(side="right")

        tk.Button(
            parent, text=t("stop_tunnel") if self._tunnel_active else t("start_tunnel"),
            font=(FONT_MONO, self._fs(8), "bold"),
            fg=FG(), bg=DANGER() if self._tunnel_active else SURFACE2(),
            activebackground=FG(), activeforeground=BG(),
            relief="flat", bd=0, cursor="hand2", padx=self._s(10), pady=self._s(8),
            command=self._toggle_tunnel_from_settings,
        ).pack(anchor="w", pady=(0, self._s(4)))

        tk.Frame(parent, bg=BORDER(), height=1).pack(fill="x", pady=self._s(10))

        self._settings_section_cloudflare(parent)

    def _toggle_tunnel_from_settings(self):
        if self._tunnel_active:
            self._stop_tunnel()
        else:
            self._start_tunnel()
        self._settings_refresh_active_section()

    def _settings_section_cloudflare(self, parent):
        from src.core import cloudflare_tunnel as cf

        tk.Label(parent, text=t("cf_domain"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(6)))

        if not cf.is_installed():
            self._responsive_wrap(tk.Label(
                parent, text=f"{t('cf_not_installed')}  {cf.CLOUDFLARED_DOWNLOAD_URL}",
                font=(FONT_MONO, self._fs(7)), fg=DANGER(), bg=SURFACE(),
            ), padding=40).pack(anchor="w", fill="x", pady=(0, self._s(8)))
            return

        hostname_var = getattr(self, "_cf_hostname_var", None)
        if hostname_var is None:
            hostname_var = tk.StringVar(value=self._cf_tunnel_hostname or "")
            self._cf_hostname_var = hostname_var

        entry_row = tk.Frame(parent, bg=SURFACE())
        entry_row.pack(fill="x", pady=(0, self._s(6)))
        entry = tk.Entry(
            entry_row, textvariable=hostname_var,
            font=(FONT_MONO, self._fs(8)), fg=FG(), bg=BG(),
            insertbackground=FG(), relief="flat", bd=0,
            highlightthickness=1, highlightbackground=BORDER(),
        )
        entry.pack(fill="x", ipady=self._s(6))
        entry.insert(0, "") if not hostname_var.get() else None

        status = cf.setup_status(hostname_var.get().strip()) if hostname_var.get().strip() else None
        status_line = t("cf_status_ready") if (status and status["tunnel_created"] and status["config_written"]) else t("cf_status_not_ready")
        tk.Label(parent, text=status_line, font=(FONT_MONO, self._fs(7)),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(6)))

        btn_row = tk.Frame(parent, bg=SURFACE())
        btn_row.pack(fill="x", pady=(0, self._s(4)))
        tk.Button(
            btn_row, text=t("cf_login"), font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            command=self._cloudflare_login,
        ).pack(side="left", padx=(0, self._s(6)))
        tk.Button(
            btn_row, text=t("cf_setup"), font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            command=lambda: self._cloudflare_setup(hostname_var.get().strip()),
        ).pack(side="left")

        if self._cf_tunnel_active:
            tk.Button(
                parent, text=t("cf_stop"), font=(FONT_MONO, self._fs(8), "bold"),
                fg=FG(), bg=DANGER(), activebackground=FG(), activeforeground=BG(),
                relief="flat", bd=0, cursor="hand2", padx=self._s(10), pady=self._s(8),
                command=self._stop_cloudflare_tunnel_from_settings,
            ).pack(anchor="w", pady=(self._s(6), 0))
            if self._cf_tunnel_url:
                url_row = tk.Frame(parent, bg=SURFACE())
                url_row.pack(fill="x", pady=(self._s(4), 0))
                tk.Label(url_row, text=self._cf_tunnel_url, font=(FONT_MONO, self._fs(8)),
                         fg=FG2(), bg=SURFACE()).pack(side="left", fill="x", expand=True, anchor="w")
                tk.Button(
                    url_row, text=t("copy"), font=(FONT_MONO, self._fs(7)),
                    fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                    relief="flat", bd=0, cursor="hand2",
                    command=lambda: self._copy(self._cf_tunnel_url),
                ).pack(side="right")
        else:
            tk.Button(
                parent, text=t("cf_start"), font=(FONT_MONO, self._fs(8), "bold"),
                fg=FG(), bg=SURFACE2(), activebackground=FG(), activeforeground=BG(),
                relief="flat", bd=0, cursor="hand2", padx=self._s(10), pady=self._s(8),
                command=lambda: self._start_cloudflare_tunnel_from_settings(hostname_var.get().strip()),
            ).pack(anchor="w", pady=(self._s(6), 0))

    def _cloudflare_login(self):
        self._log("CF-TUNNEL opening browser for cloudflared login...", "dim")

        def _worker():
            from src.core import cloudflare_tunnel as cf
            result = cf.login()
            if result.get("ok"):
                self.after(0, lambda: self._log("CF-TUNNEL login successful", "ok"))
            else:
                self.after(0, lambda: self._log(f"CF-TUNNEL login failed: {result.get('error')}", "error"))
            self.after(0, self._settings_refresh_active_section)

        threading.Thread(target=_worker, daemon=True, name="cf-login").start()

    def _cloudflare_setup(self, hostname: str):
        if not hostname:
            messagebox.showwarning(t("netshare_title"), t("cf_hostname_prompt"))
            return
        self._log(f"CF-TUNNEL setting up -> {hostname}...", "dim")

        def _worker():
            from src.core import cloudflare_tunnel as cf
            try:
                port = int(self._port_var.get())
            except ValueError:
                from src.constants import DEFAULT_PORT
                port = DEFAULT_PORT
            created = cf.create_tunnel()
            if not created.get("ok"):
                self.after(0, lambda: messagebox.showerror(t("netshare_title"), str(created.get("error"))))
                return
            routed = cf.route_dns(hostname)
            if not routed.get("ok"):
                self.after(0, lambda: messagebox.showerror(t("netshare_title"), str(routed.get("error"))))
                return
            from src.gui.server_lifecycle import PUBLIC_HTTP_PORT_OFFSET
            cf.write_config(
                created["tunnel_id"], hostname, port + PUBLIC_HTTP_PORT_OFFSET
            )
            self.after(0, lambda: self._log(f"CF-TUNNEL setup complete for {hostname}", "ok"))
            self.after(0, self._settings_refresh_active_section)

        threading.Thread(target=_worker, daemon=True, name="cf-setup").start()

    def _start_cloudflare_tunnel_from_settings(self, hostname: str):
        if not hostname:
            messagebox.showwarning(t("netshare_title"), t("cf_hostname_prompt"))
            return
        self._start_cloudflare_tunnel(hostname)
        self._settings_refresh_active_section()

    def _stop_cloudflare_tunnel_from_settings(self):
        self._stop_cloudflare_tunnel()
        self._settings_refresh_active_section()


    def _settings_section_sharing(self, parent):
        tk.Label(parent, text=t("sharing"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(6)))
        self._build_public_config_controls(parent)


    def _settings_section_permissions(self, parent):
        tk.Label(parent, text=t("config"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(6)))

        from src.core.file_index import _file_index
        profile = _file_index.profile
        gpu = f" · {profile.nvidia_name}" if profile.nvidia_detected else ""
        tk.Label(
            parent,
            text=t("hardware_profile", profile=profile.name.upper(), workers=profile.workers, gpu=gpu),
            font=(FONT_MONO, self._fs(8)), fg=FG2(), bg=SURFACE(),
        ).pack(anchor="w", pady=(0, self._s(6)))
        tk.Button(
            parent, text=t("rescan_media"), font=(FONT_MONO, self._fs(8)),
            fg=FG(), bg=SURFACE2(), relief="flat", bd=0, cursor="hand2",
            command=lambda: _file_index.rescan_media(state.ROOT_DIR),
        ).pack(anchor="w", pady=(0, self._s(10)), ipadx=self._s(6), ipady=self._s(4))

        row = tk.Frame(parent, bg=SURFACE())
        row.pack(fill="x", pady=(0, self._s(6)))
        tk.Label(row, text=t("port"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(side="left", padx=(0, self._s(6)))
        tk.Entry(
            row, textvariable=self._port_var, font=(FONT_MONO, self._fs(9)),
            fg=FG(), bg=BG(), insertbackground=FG(), relief="flat", bd=0, width=6,
            highlightthickness=1, highlightbackground=BORDER(),
        ).pack(side="left", ipady=self._s(6), padx=(0, self._s(16)))
        tk.Label(row, text=t("name"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(side="left", padx=(0, self._s(6)))
        tk.Entry(
            row, textvariable=self._name_var, font=(FONT_MONO, self._fs(9)),
            fg=FG(), bg=BG(), insertbackground=FG(), relief="flat", bd=0, width=16,
            highlightthickness=1, highlightbackground=BORDER(),
        ).pack(side="left", ipady=self._s(6))

        pw_row = tk.Frame(parent, bg=SURFACE())
        pw_row.pack(fill="x", pady=(0, self._s(6)))
        tk.Label(pw_row, text=t("local_pw"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(side="left", padx=(0, self._s(6)))
        password_entry = tk.Entry(
            pw_row, textvariable=self._password_var, font=(FONT_MONO, self._fs(9)),
            fg=FG(), bg=BG(), insertbackground=FG(), relief="flat", bd=0, width=16,
            highlightthickness=1, highlightbackground=BORDER(), show="*",
        )
        self._settings_password_entry = password_entry
        password_entry.pack(side="left", ipady=self._s(6))
        password_visible = tk.BooleanVar(value=False)

        def _toggle_password_visibility():
            visible = not password_visible.get()
            password_visible.set(visible)
            password_entry.configure(show="" if visible else "*")
            password_toggle.configure(text="HIDE" if visible else "SHOW")

        password_toggle = tk.Button(
            pw_row, text="SHOW", font=(FONT_MONO, self._fs(7), "bold"),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE2(),
            relief="flat", bd=0, cursor="hand2", padx=self._s(8),
            command=_toggle_password_visibility,
        )
        password_toggle.pack(side="left", padx=(self._s(5), 0))
        tk.Button(
            pw_row, text=t("save"), font=(FONT_MONO, self._fs(7), "bold"),
            fg=FG(), bg=SURFACE2(), activeforeground=BG(), activebackground=FG(),
            relief="flat", bd=0, cursor="hand2", padx=self._s(8), pady=self._s(4),
            command=self._save_local_password,
        ).pack(side="left", padx=(self._s(5), 0))

        reminder_row = tk.Frame(parent, bg=SURFACE())
        reminder_row.pack(fill="x", pady=(0, self._s(8)))
        tk.Label(reminder_row, text=t("password_reminder_every"),
                 font=(FONT_MONO, self._fs(8)), fg=FG3(), bg=SURFACE()).pack(side="left")
        tk.Spinbox(
            reminder_row, from_=1, to=3650,
            textvariable=self._password_reminder_days_var,
            font=(FONT_MONO, self._fs(8)), fg=FG(), bg=BG(),
            buttonbackground=SURFACE2(), insertbackground=FG(), relief="flat", bd=0,
            width=5, highlightthickness=1, highlightbackground=BORDER(),
        ).pack(side="left", padx=self._s(6), ipady=self._s(3))
        tk.Label(reminder_row, text=t("days"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(side="left")

        perm_row = tk.Frame(parent, bg=SURFACE())
        perm_row.pack(fill="x", pady=(self._s(8), 0))
        tk.Label(perm_row, text=t("write_permissions"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(4)))
        for label, var in (
            (t("allow_receiving_files"), self._allow_upload_var),
            (t("allow_document_edits"), self._allow_edit_var),
        ):
            cb = tk.Checkbutton(
                perm_row, text=label, variable=var,
                font=(FONT_MONO, self._fs(8)), fg=FG2(), bg=SURFACE(),
                activeforeground=FG(), activebackground=SURFACE(), selectcolor=BG(),
                relief="flat", bd=0, cursor="hand2", anchor="w",
            )
            cb.pack(fill="x", anchor="w")

        tk.Frame(parent, bg=BORDER(), height=1).pack(fill="x", pady=self._s(10))

        server_row = tk.Frame(parent, bg=SURFACE())
        server_row.pack(fill="x", pady=(0, self._s(10)))
        awake_label = t("keep_awake_on") if self._sleep_inhibit_enabled else t("keep_awake")
        tk.Label(server_row, text=awake_label, font=(FONT_MONO, self._fs(8)),
                 fg=FG() if self._sleep_inhibit_enabled else FG2(), bg=SURFACE()).pack(side="left")
        tk.Button(
            server_row, text=t("on") if self._sleep_inhibit_enabled else t("off"),
            font=(FONT_MONO, self._fs(7), "bold"),
            fg=FG() if self._sleep_inhibit_enabled else FG3(),
            bg=SURFACE2() if self._sleep_inhibit_enabled else SURFACE(),
            activebackground=SURFACE2(), activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2", padx=self._s(8), pady=self._s(3),
            command=self._toggle_sleep_inhibit_from_settings,
        ).pack(side="right")

        tk.Frame(parent, bg=BORDER(), height=1).pack(fill="x", pady=self._s(10))

        self._settings_section_pairing(parent)

    def _toggle_sleep_inhibit_from_settings(self):
        self._toggle_sleep_inhibit()
        self._settings_refresh_active_section()

    def _settings_section_history(self, parent):
        from datetime import datetime
        tk.Label(parent, text=t("share_history"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(8)))
        if not state.FOLDER_SHARE_HISTORY:
            tk.Label(parent, text=t("no_share_history"), font=(FONT_MONO, self._fs(8)),
                     fg=FG3(), bg=SURFACE()).pack(anchor="w")
            return
        for item in state.FOLDER_SHARE_HISTORY:
            row = tk.Frame(parent, bg=SURFACE())
            row.pack(fill="x", pady=(0, self._s(7)))
            name = Path(item["path"]).name or item["path"]
            date = datetime.fromtimestamp(item["last_shared_at"]).strftime("%Y-%m-%d %H:%M")
            tk.Label(row, text=name, font=(FONT_MONO, self._fs(8), "bold"),
                     fg=FG(), bg=SURFACE(), anchor="w").pack(fill="x")
            tk.Label(row, text=t("share_history_detail", count=item["share_count"], date=date),
                     font=(FONT_MONO, self._fs(7)), fg=FG3(), bg=SURFACE(), anchor="w").pack(fill="x")
            tk.Label(row, text=item["path"], font=(FONT_MONO, self._fs(7)),
                     fg=FG2(), bg=SURFACE(), anchor="w").pack(fill="x")
        tk.Button(parent, text=t("clear_history"), font=(FONT_MONO, self._fs(7), "bold"),
                  fg=DANGER(), bg=SURFACE2(), relief="flat", bd=0, cursor="hand2",
                  command=self._clear_share_history).pack(anchor="w", pady=(self._s(8), 0))

    def _clear_share_history(self):
        if not messagebox.askyesno(t("clear_history"), t("clear_history_confirm"), default="no"):
            return
        state.clear_folder_share_history()
        self._folder_history = []
        self._refresh_history()
        self._settings_refresh_active_section()

    def _settings_section_pairing(self, parent):
        tk.Label(parent, text=t("local_pairing"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(4)))

        code_var = tk.StringVar(value=state.WRITE_OTP or "")
        code_row = tk.Frame(parent, bg=SURFACE())
        code_row.pack(fill="x", pady=(0, self._s(6)))
        tk.Label(code_row, text=t("current_code"), font=(FONT_MONO, self._fs(7)),
                 fg=FG3(), bg=SURFACE()).pack(side="left", padx=(0, self._s(6)))
        code_label = tk.Label(code_row, textvariable=code_var, font=(FONT_MONO, self._fs(9), "bold"),
                               fg=FG(), bg=SURFACE())
        code_label.pack(side="left")

        def _start_pairing():
            code = state.reset_write_auth()
            code_var.set(code)
            self._log(f"WRITE OTP {code}", "dim")

        tk.Button(
            parent, text=t("start_pairing"), font=(FONT_MONO, self._fs(7)),
            fg=FG3(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
            relief="flat", bd=0, cursor="hand2",
            command=_start_pairing,
        ).pack(anchor="w", pady=(0, self._s(8)))

        tk.Label(parent, text=t("trusted_devices"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(4)))
        if not state.TRUSTED_DEVICES:
            tk.Label(parent, text=t("no_devices_paired"), font=(FONT_MONO, self._fs(7)),
                     fg=FG3(), bg=SURFACE()).pack(anchor="w")
        else:
            from datetime import datetime
            for device_id, registered_at in sorted(state.TRUSTED_DEVICES.items()):
                dev_row = tk.Frame(parent, bg=SURFACE())
                dev_row.pack(fill="x", pady=(0, self._s(3)))
                date = datetime.fromtimestamp(float(registered_at)).strftime("%Y-%m-%d %H:%M")
                tk.Label(dev_row, text=f"{device_id}  {date}", font=(FONT_MONO, self._fs(7)),
                         fg=FG2(), bg=SURFACE(), anchor="w").pack(side="left", fill="x", expand=True)
                tk.Button(
                    dev_row, text=t("revoke"), font=(FONT_MONO, self._fs(7)),
                    fg=DANGER(), bg=SURFACE(), activeforeground=FG(), activebackground=SURFACE(),
                    relief="flat", bd=0, cursor="hand2",
                    command=lambda d=device_id: self._revoke_device_from_settings(d),
                ).pack(side="right")

    def _revoke_device_from_settings(self, device_id: str):
        state.revoke_device(device_id)
        self._log(f"PAIR   revoked {device_id}", "dim")
        self._settings_refresh_active_section()

    # Updates -- placeholder, per the agreed scope (no real update mechanism
    # exists in the repo today; not implementing version-check logic without
    # a confirmed update channel/source to check against).

    def _settings_section_updates(self, parent):
        tk.Label(parent, text=t("current_version"), font=(FONT_MONO, self._fs(9), "bold"),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(4)))
        tk.Label(parent, text=f"V{VERSION}", font=(FONT_MONO, self._fs(10)),
                 fg=FG(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(10)))
        tk.Button(
            parent, text=t("check_for_updates"), font=(FONT_MONO, self._fs(8)),
            fg=FG3(), bg=SURFACE2(), activebackground=SURFACE2(), activeforeground=FG(),
            relief="flat", bd=0, cursor="hand2", padx=self._s(10), pady=self._s(8),
            state="disabled",
        ).pack(anchor="w")
        tk.Label(parent, text=t("update_placeholder"), font=(FONT_MONO, self._fs(7)),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(self._s(6), 0))

    # About

    def _settings_section_about(self, parent):
        tk.Label(parent, text=t("netshare_player"), font=(FONT_MONO, self._fs(10), "bold"),
                 fg=FG(), bg=SURFACE()).pack(anchor="w")
        tk.Label(parent, text=f"V{VERSION}", font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(self._s(2), self._s(2)))
        tk.Label(parent, text=t("legal_company"), font=(FONT_MONO, self._fs(8)),
                 fg=FG3(), bg=SURFACE()).pack(anchor="w", pady=(0, self._s(10)))
        self._responsive_wrap(tk.Label(
            parent, text=f"!  {t('footer_warning')}", font=(FONT_MONO, self._fs(8)),
            fg=DANGER(), bg=SURFACE(), justify="left",
        ), padding=40).pack(anchor="w", fill="x")
