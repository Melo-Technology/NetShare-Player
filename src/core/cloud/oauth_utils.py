"""
Shared OAuth 2.0 installed-app helpers (PKCE + loopback callback).

The callback listener is intentionally defensive: browsers and local software
may request ``/favicon.ico`` or probe the loopback port before the real OAuth
redirect arrives.  Only a callback on ``/`` with the expected state and either
``code`` or ``error`` is terminal.  Everything else is ignored until the
bounded deadline expires.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

CALLBACK_SUCCESS_HTML = (
    "<html><body style='font-family:sans-serif;text-align:center;padding-top:4em'>"
    "<h2>NetShare Server</h2>"
    "<p>Authorization was received. NetShare is still finalizing the connection.</p>"
    "<p>Return to the app and wait for its confirmation before closing this tab.</p>"
    "</body></html>"
).encode("utf-8")

CALLBACK_REJECTED_HTML = (
    "<html><body style='font-family:sans-serif;text-align:center;padding-top:4em'>"
    "<h2>NetShare Server</h2>"
    "<p>This callback did not match the active authorization request and was ignored.</p>"
    "<p>Return to the authorization tab and try again.</p>"
    "</body></html>"
).encode("utf-8")


def generate_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def generate_state() -> str:
    return secrets.token_urlsafe(16)


class _CallbackHandler(BaseHTTPRequestHandler):
    server_version = "NetShareOAuth/1"
    sys_version = ""

    def _send(self, status: int, body: bytes = b"", content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        if body:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/":
            # Browser favicon/probe requests must never consume the one OAuth
            # callback the provider is waiting for.
            self._send(204, b"")
            return

        params = parse_qs(parsed.query, keep_blank_values=True)
        expected_state = str(getattr(self.server, "expected_state", "") or "")  # type: ignore[attr-defined]
        received_state = str(params.get("state", [""])[0] or "")
        has_terminal_value = "code" in params or "error" in params
        if not has_terminal_value or (expected_state and received_state != expected_state):
            self._send(400, CALLBACK_REJECTED_HTML)
            return

        # Store only after all callback invariants are satisfied.  The OAuth
        # code is kept in process memory just long enough for token exchange;
        # it is never logged by this handler.
        self.server.result = params  # type: ignore[attr-defined]
        self._send(200, CALLBACK_SUCCESS_HTML)

    def log_message(self, fmt, *args):
        # Avoid leaking OAuth query strings (which contain authorization codes)
        # into HTTP/desktop diagnostics.
        pass


def start_callback_server(port: int = 0, *, expected_state: str = "") -> tuple[HTTPServer, int]:
    """Bind the provider callback server to loopback only."""
    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server.result = None  # type: ignore[attr-defined]
    server.expected_state = str(expected_state or "")  # type: ignore[attr-defined]
    return server, server.server_address[1]


def wait_for_callback(
    server: HTTPServer,
    timeout: int = 180,
    *,
    expected_state: str = "",
) -> dict | None:
    """Wait until a valid OAuth redirect or a bounded deadline.

    Invalid paths, browser probes and wrong-state callbacks are non-terminal and
    therefore cannot steal the active OAuth attempt.  ``server_close`` always
    runs, including timeout and unexpected handler errors.
    """
    expected = str(expected_state or "")
    if expected:
        server.expected_state = expected  # type: ignore[attr-defined]
    deadline = time.monotonic() + max(0.0, float(timeout))
    try:
        while getattr(server, "result", None) is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            server.timeout = min(0.5, remaining)
            server.handle_request()
        result = getattr(server, "result", None)
        return dict(result) if isinstance(result, dict) else None
    finally:
        server.server_close()


def open_browser(url: str):
    return webbrowser.open(url)
