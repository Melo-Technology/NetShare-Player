"""
Core primitives shared by every route mixin: logging overrides, JSON
response helpers, request-body reading, and CORS.

Every other mixin (auth, routes/*) assumes these methods exist on `self`.
This class holds no route logic of its own.
"""

import json
from urllib.parse import urlparse

import src.state as state
from src.core.errors.error_mapper import enrich_error_payload, map_api_error
from src.secret_redaction import redact_secret_text
from .tunnel import _is_tunnel_request, _trusted_forwarded_client_ip

_CLIENT_DISCONNECT_ERRORS = (
    BrokenPipeError,
    ConnectionResetError,
    ConnectionAbortedError,
)

_ALLOWED_BROWSER_ORIGINS = {
    ("http", "localhost"),
    ("http", "127.0.0.1"),
    ("http", "::1"),
    ("capacitor", "localhost"),
    ("ionic", "localhost"),
}


def _is_allowed_browser_origin(origin: str) -> bool:
    """Validate an Origin by exact scheme/host matching, with any valid port."""
    try:
        parsed = urlparse(origin)
        _ = parsed.port  # Force validation of malformed ports.
    except ValueError:
        return False
    normalized = origin.rstrip("/")
    return bool(
        parsed.scheme
        and parsed.hostname
        and (
            (parsed.scheme.lower(), parsed.hostname.lower()) in _ALLOWED_BROWSER_ORIGINS
            or normalized in state.WEB_ALLOWED_ORIGINS
        )
        and parsed.username is None
        and parsed.password is None
        and parsed.path in ("", "/")
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )


class NetShareHandlerBase:
    """Logging, response helpers, and body reading shared by all route mixins."""

    # Logging overrides

    def _is_tls_probe(self) -> bool:
        raw_requestline = getattr(self, "raw_requestline", b"")
        return (
            isinstance(raw_requestline, bytes)
            and len(raw_requestline) >= 3
            and raw_requestline[:2] == b"\x16\x03"
            and raw_requestline[2] <= 0x04
        )

    def log_message(self, fmt, *args):
        pass   # suppress default stderr output

    def log_request(self, code="-", size="-"):
        status = str(code)
        if (
            status == "400"
            and self._is_tls_probe()
            and getattr(self, "_tls_bad_request_version", False)
        ):
            state._emit(
                "TLS probe received on plaintext port; client may fall back to HTTP",
                "info",
            )
            return
        kind   = "error" if status[0] in ("4", "5") else "info"
        command = getattr(self, "command", None) or "<invalid>"
        path = getattr(self, "path", None) or "<invalid>"
        if path.startswith("/api/v2/web/download/"):
            path = "/api/v2/web/download/<redacted>"
        elif path.startswith("/api/v2/web/media/"):
            path = "/api/v2/web/media/<redacted>"
        client_address = getattr(self, "client_address", None)
        client_ip = (
            client_address[0]
            if client_address and client_address[0] is not None
            else "<unknown>"
        )
        state._emit(
            redact_secret_text(f"{command:<8} {path}  ->  {code}  [{client_ip}]"),
            kind,
        )

    def log_error(self, fmt, *args):
        if (
            self._is_tls_probe()
            and fmt == "code %d, message %s"
            and len(args) >= 2
            and args[0] == 400
            and str(args[1]).startswith("Bad request version")
        ):
            self._tls_bad_request_version = True
            return
        state._emit(redact_secret_text(f"ERROR  {fmt % args}"), "error")

    # Response helpers

    def send_error(self, code, message=None, explain=None):
        if (
            getattr(self, "command", None) is None
            and getattr(self, "request_version", None) == self.default_request_version
        ):
            self.request_version = "HTTP/1.0"
        return super().send_error(code, message, explain)

    def end_headers(self):
        """Apply baseline browser protections to every NetShare response."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def send_json(self, data, status=200, headers=None):
        try:
            if isinstance(data, dict) and isinstance(data.get("error"), str):
                data = enrich_error_payload(data, status=status)
            body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type",   "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
        except _CLIENT_DISCONNECT_ERRORS:
            pass

    def send_error_json(
        self, msg: str, status: int = 400, *, code=None, domain=None,
        severity="error", support_code=None, headers=None,
    ):
        try:
            if status == 404 and str(msg) == "Unknown endpoint":
                try:
                    from src.runtime.security_monitor_runtime import security_monitor_runtime
                    security_monitor_runtime.record_not_found(
                        ip=self._client_ip(),
                        method=str(getattr(self, "command", "") or ""),
                        path=urlparse(str(getattr(self, "path", "") or "")).path,
                    )
                except Exception:
                    pass
            mapped = map_api_error(
                msg, status=status, code=code, domain=domain,
                severity=severity, support_code=support_code,
            )
            self.send_json(mapped.payload(), status, headers=headers)
        except _CLIENT_DISCONNECT_ERRORS:
            pass

    def _read_body(self, max_bytes: int, allow_empty: bool = False) -> bytes | None:
        length = self._content_length()
        if length is None:
            return None
        if length == 0 and not allow_empty:
            self.send_error_json("Empty request body", 400)
            return None
        if length > max_bytes:
            self.send_error_json("Request body too large", 413)
            return None
        return self.rfile.read(length)

    def _content_length(self) -> int | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error_json("Invalid Content-Length", 400)
            return None
        if length < 0:
            self.send_error_json("Invalid Content-Length", 400)
            return None
        return length

    def _send_cors_headers(self) -> bool:
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        if self._is_allowed_cors_origin():
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            return True
        return False

    def _is_allowed_cors_origin(self) -> bool:
        origin = self.headers.get("Origin", "")
        return _is_allowed_browser_origin(origin)

    def _rate_key(self, scope: str) -> str:
        return f"{scope}:{self._client_ip()}"

    def _enforce_web_rate(self, scope: str, identity: str, limit: int, window: int) -> bool:
        allowed, retry_after = state.WEB_RATE_LIMITER.allow(
            scope, identity, limit=limit, window=window,
        )
        if allowed:
            return True
        self.send_error_json(
            "Too many web requests", 429, code="web.auth.rate_limited",
            domain="web.auth", headers={
                "Retry-After": str(retry_after), "Cache-Control": "no-store",
                "Pragma": "no-cache", "Vary": "Origin",
            },
        )
        return False

    def _client_ip(self) -> str:
        return _trusted_forwarded_client_ip(self) or self.client_address[0]

    def _security_preflight(self) -> bool:
        """Apply the maintenance gate, persistent blocks and burst detection."""
        try:
            from src.core.local_data_reset import maintenance_reset_active
            if maintenance_reset_active():
                self.send_error_json(
                    "Server maintenance in progress",
                    503,
                    code="maintenance.reset_in_progress",
                    domain="maintenance",
                    headers={"Retry-After": "1", "Cache-Control": "no-store"},
                )
                return False
        except Exception:
            # A maintenance-gate import failure must not make the network stack
            # unavailable. Normal auth/security checks still run below.
            pass
        try:
            from src.runtime.security_monitor_runtime import security_monitor_runtime
            decision = security_monitor_runtime.inspect_request(
                ip=self._client_ip(),
                method=str(getattr(self, "command", "") or ""),
                path=urlparse(str(getattr(self, "path", "") or "")).path,
            )
        except Exception:
            # Security telemetry must fail open if its local persistence is
            # unavailable; existing authentication/rate limits remain active.
            return True
        if decision.allowed:
            return True
        headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
        if decision.retry_after > 0:
            headers["Retry-After"] = str(decision.retry_after)
        self.send_error_json(
            "Request temporarily blocked by NetShare security policy",
            429,
            code="security.ip_blocked",
            domain="security",
            headers=headers,
        )
        return False

    def _security_auth_failure(self, kind: str) -> None:
        try:
            from src.runtime.security_monitor_runtime import security_monitor_runtime
            security_monitor_runtime.record_auth_failure(
                ip=self._client_ip(),
                kind=str(kind or "password"),
                path=urlparse(str(getattr(self, "path", "") or "")).path,
            )
        except Exception:
            pass

    def _security_auth_success(self) -> None:
        try:
            from src.runtime.security_monitor_runtime import security_monitor_runtime
            security_monitor_runtime.record_auth_success(ip=self._client_ip())
        except Exception:
            pass

    def _reject_spoofed_tunnel_header(self) -> bool:
        if not _is_tunnel_request(self) and self.headers.get("X-Tunnel") is not None:
            self.send_error_json("X-Tunnel is not accepted on the LAN listener", 400)
            return True
        external_header = state.EXTERNAL_TUNNEL_TRUSTED_HEADER.strip()
        if (
            external_header
            and self.headers.get(external_header) is not None
            and not _is_tunnel_request(self)
        ):
            self.send_error_json(
                f"{external_header} is not accepted from an untrusted proxy",
                400,
            )
            return True
        return False
