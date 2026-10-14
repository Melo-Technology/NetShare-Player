"""API v2 share-ticket management and minimal token-authenticated web page."""

import html
import json
from pathlib import Path
from urllib.parse import quote, unquote

from src.core.shared_paths import resolve_shared_path
from src.core.share_tickets import ShareTicketError, share_ticket_store
from ..tunnel import _uses_public_access_policy


class ShareTicketRoutesMixin:
    def _ticket_scope(self) -> str:
        return "tunnel" if _uses_public_access_policy(self) else "lan"

    def _route_share_ticket_create(self):
        body = self._read_body(64 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            paths = payload.get("paths") if isinstance(payload, dict) else None
            for path in paths or []:
                self._shared_target(str(path))
            ticket = share_ticket_store.create(
                paths,
                int(payload.get("ttl_seconds", 900)),
                int(payload.get("max_accesses", 1)),
                payload.get("allow_download") is True,
                self._ticket_scope(),
            )
            ticket["url_path"] = f"/s/{ticket['token']}"
            self.send_json(ticket, 201)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            self.send_error_json("Invalid ticket request", 400)
        except (ShareTicketError, FileNotFoundError) as error:
            self.send_error_json(str(error), 400)

    def _route_share_ticket_revoke(self, ticket_id: str):
        if share_ticket_store.revoke(ticket_id):
            return self.send_json({"ok": True})
        self.send_error_json("Share ticket not found", 404)

    def _route_shared_page(self, token: str):
        grant = share_ticket_store.inspect(token, self._ticket_scope())
        if grant is None:
            return self._send_share_error(404, "This share is unavailable or expired.")
        links = []
        for path in grant.paths:
            name = Path(path).name or "Shared item"
            href = f"/s/{quote(token, safe='')}/file?path={quote(path, safe='')}"
            action = "Download" if grant.allow_download else "Open"
            links.append(f'<li><a href="{href}">{html.escape(name)}</a> <span>{action}</span></li>')
        document = (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<meta name=\"robots\" content=\"noindex,nofollow,noarchive\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>NetShare</title></head><body><main><h1>NETSHARE</h1>"
            "<p>Local network share. Respect the owner&apos;s copyright.</p><ul>"
            + "".join(links)
            + "</ul></main></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(document))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(document)

    def _route_shared_file(self, token: str, params):
        grant = share_ticket_store.inspect(token, self._ticket_scope())
        requested = unquote(params.get("path", [""])[0])
        if grant is None or requested not in grant.paths:
            return self.send_error_json("Shared file not found", 404)
        try:
            target = self._shared_target(requested)
            if not target.is_file():
                raise FileNotFoundError("Shared file not found")
        except (OSError, FileNotFoundError):
            return self.send_error_json("Shared file not found", 404)
        grant = share_ticket_store.consume(token, self._ticket_scope())
        if grant is None:
            return self.send_error_json("Shared file not found", 404)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", target.stat().st_size)
        self.send_header("Content-Disposition", f"{'attachment' if grant.allow_download else 'inline'}; filename*=UTF-8''{quote(target.name)}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            with target.open("rb") as shared_file:
                while True:
                    chunk = shared_file.read(self._CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def _shared_target(self, path: str) -> Path:
        resolved = resolve_shared_path(path, visible=True)
        if resolved is None:
            raise FileNotFoundError("Shared path not found")
        return resolved.path

    def _send_share_error(self, status: int, message: str):
        body = f"<!doctype html><html><body><h1>NETSHARE</h1><p>{html.escape(message)}</p></body></html>".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)
