"""
Shared OAuth 2.0 "installed app" helpers (PKCE + local loopback callback
server), used by both the Google Drive and Dropbox providers so neither
needs to embed a client secret or run its own web server implementation.

Flow:
    1. generate_pkce_pair()               -> (verifier, challenge)
    2. start_callback_server()            -> local HTTPServer bound to 127.0.0.1
    3. build the provider's auth URL with redirect_uri=http://127.0.0.1:<port>/
       and code_challenge=<challenge>, open it with webbrowser.open()
    4. wait_for_callback(server)          -> blocks until the browser redirects
       back with ?code=...&state=..., or until timeout
    5. exchange the code + verifier for tokens via the provider's token endpoint
"""

import base64
import hashlib
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

CALLBACK_SUCCESS_HTML = (
    "<html><body style='font-family:sans-serif;text-align:center;padding-top:4em'>"
    "<h2>NetShare Server</h2><p>You can close this tab and return to the app.</p>"
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
    def do_GET(self):
        parsed = urlparse(self.path)
        self.server.result = parse_qs(parsed.query)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(CALLBACK_SUCCESS_HTML)))
        self.end_headers()
        self.wfile.write(CALLBACK_SUCCESS_HTML)

    def log_message(self, fmt, *args):
        pass  # keep the OAuth dance out of the app's log stream


def start_callback_server(port: int = 0) -> tuple[HTTPServer, int]:
    """Bind a one-shot local HTTP server on 127.0.0.1. port=0 lets the OS
    pick a free port (returned as the second value)."""
    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server.result = None  # type: ignore[attr-defined]
    return server, server.server_address[1]


def wait_for_callback(server: HTTPServer, timeout: int = 180) -> dict | None:
    """Block for a single incoming request (the OAuth redirect) up to
    *timeout* seconds. Returns the parsed query params, or None on timeout."""
    server.timeout = timeout
    server.handle_request()
    result = getattr(server, "result", None)
    server.server_close()
    return result


def open_browser(url: str):
    webbrowser.open(url)
