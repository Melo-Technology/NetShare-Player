"""
HTTP request handler for NetShare Server.

NetShareHandler is a BaseHTTPRequestHandler subclass that serves all
API routes used by the Flutter mobile client:

    GET /ping           server info + auth mode
    GET /list           directory listing
    GET /search         file-index search
    GET /file           full / ranged file download
    GET /thumbnail      image thumbnail (Pillow) or video frame (ffmpeg)
    GET /art            MP3 cover-art extraction
    GET /document       read text document (UTF-8)
    GET /setup-totp     local pairing QR + secret
    POST /register-device trust a local device with TOTP
    POST /upload        file upload with optional overwrite
    PUT /document       write text document (UTF-8)
"""

import json
import mimetypes
import os
import socket
import time
import hmac
import ipaddress
import base64
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse, quote

import src.state as state
from src.constants import VERSION
from src.deps import HAS_PIL, HAS_FFMPEG, FFMPEG_BIN
from src.utils.network import safe_path, file_info, extract_cover_from_mp3

if HAS_PIL:
    from PIL import Image as PilImage

MAX_UPLOAD_BYTES = 512 * 1024 * 1024
MAX_TEXT_EDIT_BYTES = 2 * 1024 * 1024

_TEXT_EDIT_EXTS = {
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".xml", ".html",
    ".htm", ".css", ".js", ".py", ".log", ".ini", ".conf", ".yaml", ".yml",
    ".rtf",
}

_ALLOWED_BROWSER_ORIGINS = (
    "http://localhost",
    "http://127.0.0.1",
    "http://[::1]",
    "capacitor://localhost",
    "ionic://localhost",
)


# Tunnel detection

def _is_tunnel_request(handler) -> bool:
    """
    Return True when the request is forwarded through the public SSH tunnel.

    localhost.run connects back to 127.0.0.1, so the only reliable signal is
    the X-Tunnel: 1 header that the Flutter app sets when using the public URL.
    We only honour this header when TUNNEL_ACTIVE is True, preventing spoofing.
    """
    if not state.TUNNEL_ACTIVE:
        return False
    if handler.headers.get("X-Tunnel", "").strip() != "1":
        return False
    try:
        return ipaddress.ip_address(handler.client_address[0]).is_loopback
    except ValueError:
        return False


def _is_lan_request(handler) -> bool:
    try:
        ip = ipaddress.ip_address(handler.client_address[0])
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


# HTTP handler

class NetShareHandler(BaseHTTPRequestHandler):

    # Logging overrides

    def log_message(self, fmt, *args):
        pass   # suppress default stderr output

    def log_request(self, code="-", size="-"):
        status = str(code)
        kind   = "error" if status[0] in ("4", "5") else "info"
        state._emit(
            f"{self.command:<8} {self.path}  ->  {code}  [{self.client_address[0]}]",
            kind,
        )

    def log_error(self, fmt, *args):
        state._emit(f"ERROR  {fmt % args}", "error")

    # Response helpers

    def send_json(self, data, status=200):
        try:
            body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type",   "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_error_json(self, msg: str, status: int = 400):
        try:
            self.send_json({"error": msg}, status)
        except (BrokenPipeError, ConnectionResetError):
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
        return bool(origin and origin.startswith(_ALLOWED_BROWSER_ORIGINS))

    def _rate_key(self, scope: str) -> str:
        return f"{scope}:{self.client_address[0]}"

    # Auth

    def _check_password(self) -> bool:
        """
        Validate the X-Password header against the correct password for this
        request context (tunnel vs. LAN).  Empty password = open access.
        """
        via_tunnel = _is_tunnel_request(self)
        key = self._rate_key("password:tunnel" if via_tunnel else "password:local")
        if not state.auth_attempt_allowed(key):
            self._auth_rate_limited = True
            return False
        if via_tunnel:
            community = state.COMMUNITY_PASSWORD
            admin = state.ADMIN_PASSWORD or state.TUNNEL_PASSWORD
            if not community and not admin:
                return True
            received = unquote(self.headers.get("X-Password", "")).strip()
            ok = bool(
                (community and hmac.compare_digest(received, community)) or
                (admin and hmac.compare_digest(received, admin))
            )
        else:
            if not state.LOCAL_PASSWORD:
                return True
            received = unquote(self.headers.get("X-Password", "")).strip()
            ok = hmac.compare_digest(received, state.LOCAL_PASSWORD)
        if ok:
            state.clear_auth_failures(key)
        else:
            state.record_auth_failure(key)
        return ok

    def _public_role(self) -> str:
        if not _is_tunnel_request(self):
            return ""
        received = unquote(self.headers.get("X-Password", "")).strip()
        admin = state.ADMIN_PASSWORD or state.TUNNEL_PASSWORD
        if admin and hmac.compare_digest(received, admin):
            return "admin"
        if state.COMMUNITY_PASSWORD and hmac.compare_digest(received, state.COMMUNITY_PASSWORD):
            return "community"
        if not admin and not state.COMMUNITY_PASSWORD:
            return "admin"
        return ""

    def _has_full_write_access(self) -> bool:
        if _is_tunnel_request(self):
            return self._public_role() == "admin"
        return state.is_trusted_device(self.headers.get("X-Device-ID", ""))

    def _has_upload_access(self) -> bool:
        if _is_tunnel_request(self):
            role = self._public_role()
            return role == "admin" or (
                role == "community" and state.COMMUNITY_UPLOAD
            )
        return self._has_full_write_access()

    def _community_home(self) -> str:
        return "/" if state.COMMUNITY_BROWSE_ROOT else "/incoming"

    # OPTIONS (CORS pre-flight)

    def do_OPTIONS(self):
        if self.headers.get("Origin") and not self._is_allowed_cors_origin():
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(200)
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-Password, X-Device-ID, X-Tunnel, X-File-Path-B64, X-Filename, X-Upload-Token, Content-Type, Range")
        self.end_headers()

    # GET router

    def do_GET(self):
        parsed   = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params   = parse_qs(parsed.query)

        if endpoint == "/ping":
            self._route_ping(params)
            return

        if endpoint == "/setup-totp":
            self._route_setup_totp()
            return

        if not self._check_password():
            self.send_error_json("Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized", 429 if getattr(self, "_auth_rate_limited", False) else 401)
            return

        if endpoint == "/list":
            self._route_list(params)
        elif endpoint == "/search":
            self._route_search(params)
        elif endpoint == "/file":
            self._route_file(params)
        elif endpoint == "/thumbnail":
            self._route_thumbnail(params)
        elif endpoint == "/art":
            self._route_art(params)
        elif endpoint == "/document":
            if not self._has_full_write_access():
                self.send_error_json("Trusted device or admin key required", 403)
                return
            self._route_document_get(params)
        elif endpoint == "/upload-request":
            if not self._has_upload_access():
                self.send_error_json("Trusted device or upload key required", 403)
                return
            self._route_upload_request_status(params)
        else:
            self.send_error_json("Unknown endpoint", 404)

    # POST / PUT routers

    def do_POST(self):
        parsed   = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params   = parse_qs(parsed.query)

        if endpoint == "/register-device":
            self._route_register_device()
            return

        if not self._check_password():
            self.send_error_json("Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized", 429 if getattr(self, "_auth_rate_limited", False) else 401)
            return
        if endpoint == "/upload":
            if not self._has_upload_access():
                self.send_error_json("Trusted device or upload key required", 403)
                return
            self._route_upload(params)
        elif endpoint == "/upload-request":
            if not self._has_upload_access():
                self.send_error_json("Trusted device or upload key required", 403)
                return
            self._route_upload_request_create()
        else:
            self.send_error_json("Unknown endpoint", 404)

    def do_PUT(self):
        parsed   = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params   = parse_qs(parsed.query)

        if not self._check_password():
            self.send_error_json("Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized", 429 if getattr(self, "_auth_rate_limited", False) else 401)
            return
        if not self._has_full_write_access():
            self.send_error_json("Trusted device or admin key required", 403)
            return

        if endpoint == "/document":
            self._route_document_put(params)
        else:
            self.send_error_json("Unknown endpoint", 404)

    # Route implementations

    def _route_ping(self, params):
        """Return server metadata and feature availability to the client."""
        from src.core.file_index import _file_index
        via_tunnel = _is_tunnel_request(self)
        public_role = self._public_role() if via_tunnel else ""
        device_id = self.headers.get("X-Device-ID", "").strip()
        ws_port    = None
        if state._ws_manager is not None:
            try:
                ws_port = int(self.server.server_address[1]) + 1
            except Exception:
                pass
        self.send_json({
            "name":               state.SERVER_NAME,
            "version":            VERSION,
            "root":               state.ROOT_DIR.name or str(state.ROOT_DIR),
            "ws_port":            ws_port,
            "index_ready":        _file_index.ready,
            "index_total":        _file_index.total,
            "requires_password":  bool(
                (state.COMMUNITY_PASSWORD or state.ADMIN_PASSWORD or state.TUNNEL_PASSWORD)
                if via_tunnel else state.LOCAL_PASSWORD
            ),
            "access_mode":        "tunnel" if via_tunnel else "local",
            "mode":               "public" if via_tunnel else "local",
            "public_role":        public_role,
            "trusted":            state.is_trusted_device(device_id) if device_id and not via_tunnel else False,
            "features": {
                "upload":          bool(state.FEATURE_FLAGS.get("upload"))
                                   and (public_role != "community" or state.COMMUNITY_UPLOAD),
                "download":        public_role != "community" or state.COMMUNITY_DOWNLOAD,
                "browse_root":     public_role != "community" or state.COMMUNITY_BROWSE_ROOT,
                "document_edit":   bool(state.FEATURE_FLAGS.get("document_edit"))
                                   and public_role != "community",
                "write_pairing":   bool(state.FEATURE_FLAGS.get("write_pairing"))
                                   and not via_tunnel,
                "write_otp_ttl":   0,
                "write_token_ttl": 0,
                "editable_extensions": sorted(_TEXT_EDIT_EXTS),
                "office_edit_mode": "download_edit_upload",
                "public_upload_mode": state.PUBLIC_UPLOAD_MODE,
            },
        })

    def _route_setup_totp(self):
        """Create a TOTP secret and QR payload for local trusted-device pairing."""
        if _is_tunnel_request(self) or not _is_lan_request(self):
            return self.send_error_json("Local network only", 403)
        if not self._check_password():
            return self.send_error_json(
                "Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized",
                429 if getattr(self, "_auth_rate_limited", False) else 401,
            )
        try:
            import qrcode
            uri = state.pyotp.TOTP(state.TOTP_SECRET).provisioning_uri(
                name=state.SERVER_NAME,
                issuer_name="NetShare Server",
            )
            img = qrcode.make(uri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            qr_png = base64.b64encode(buf.getvalue()).decode("ascii")
            return self.send_json({
                "secret": state.TOTP_SECRET,
                "otpauth_uri": uri,
                "qr_png": qr_png,
            })
        except Exception as e:
            return self.send_error_json(f"Could not build TOTP QR: {e}", 500)

    def _route_register_device(self):
        """Register a trusted device after validating its one-time TOTP code."""
        if _is_tunnel_request(self) or not _is_lan_request(self):
            return self.send_error_json("Local network only", 403)
        if not self._check_password():
            return self.send_error_json(
                "Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized",
                429 if getattr(self, "_auth_rate_limited", False) else 401,
            )
        key = self._rate_key("totp-register")
        if not state.auth_attempt_allowed(key):
            return self.send_error_json("Too many TOTP attempts", 429)
        body = self._read_body(8 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_error_json("Invalid JSON body", 400)
        if not state.register_device(
            str(payload.get("device_id", "")).strip(),
            str(payload.get("code", "")).strip(),
        ):
            state.record_auth_failure(key)
            return self.send_error_json("Invalid TOTP code", 403)
        state.clear_auth_failures(key)
        self.send_json({"ok": True})

    def _route_list(self, params):
        rel    = params.get("path", ["/"])[0]
        if _is_tunnel_request(self) and self._public_role() == "community":
            if not state.COMMUNITY_BROWSE_ROOT:
                rel = "/incoming"
                try:
                    (state.ROOT_DIR / "incoming").mkdir(parents=True, exist_ok=True)
                except OSError:
                    pass
        target = state.ROOT_DIR if rel in ("/", "") else safe_path(rel)
        if target is None:
            return self.send_error_json("Invalid path", 403)
        if not target.exists():
            return self.send_error_json("Directory not found", 404)
        if not target.is_dir():
            return self.send_error_json("Not a directory", 400)
        try:
            items = []
            for entry in sorted(
                target.iterdir(),
                key=lambda e: (not e.is_dir(), e.name.lower()),
            ):
                try:
                    if entry.name.startswith("."):
                        continue
                    items.append(file_info(entry, state.ROOT_DIR))
                except (PermissionError, OSError):
                    pass
            self.send_json(items)
        except PermissionError:
            self.send_error_json("Permission denied", 403)

    def _route_search(self, params):
        """Search the file index or invalidate and rebuild it on demand."""
        from src.core.file_index import _file_index
        if _is_tunnel_request(self) and self._public_role() == "community":
            return self.send_error_json("Search is not available for community access", 403)
        if params.get("invalidate"):
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            _file_index.clear()
            _file_index.invalidate_cache(state.ROOT_DIR)
            _file_index.build(state.ROOT_DIR)
            return self.send_json({"ok": True, "message": "cache invalidated, reindexing"})
        if params.get("ready"):
            return self.send_json({"ready": _file_index.ready, "total": _file_index.total})
        query = params.get("q", [""])[0]
        if not query.strip():
            return self.send_json({"items": [], "total": 0, "offset": 0, "has_more": False})
        try:
            limit  = min(int(params.get("limit",  ["50"])[0]), 200)
        except (ValueError, IndexError):
            limit = 50
        try:
            offset = max(int(params.get("offset", ["0"])[0]), 0)
        except (ValueError, IndexError):
            offset = 0
        file_type = params.get("type", ["all"])[0]
        self.send_json(_file_index.search(query, limit=limit, offset=offset, file_type=file_type))

    def _route_file(self, params):
        rel = params.get("path", [""])[0]
        if not rel:
            b64 = self.headers.get("X-File-Path-B64", "")
            if b64:
                try:
                    import base64 as _b64
                    rel = _b64.urlsafe_b64decode(b64 + "==").decode("utf-8")
                except Exception:
                    return self.send_error_json("Invalid X-File-Path-B64 header", 400)
        if not rel:
            return self.send_error_json("Missing 'path' parameter", 400)
        target = safe_path(rel)
        if target is None:
            return self.send_error_json("Invalid path", 403)
        if not target.exists():
            return self.send_error_json("File not found", 404)
        if not target.is_file():
            return self.send_error_json("Not a file", 400)
        try:
            file_size = target.stat().st_size
            mime, _   = mimetypes.guess_type(str(target))
            mime      = mime or "application/octet-stream"
            if mime.startswith("text/") or mime in (
                "application/json",
                "application/xml",
                "application/javascript",
                "application/ld+json",
            ):
                mime = f"{mime}; charset=utf-8"
            range_hdr = self.headers.get("Range")
            if range_hdr:
                self._serve_range(target, file_size, mime, range_hdr)
            else:
                self._serve_full(target, file_size, mime)
        except PermissionError:
            self.send_error_json("Permission denied", 403)
        except Exception as e:
            self.send_error_json(f"Server error: {e}", 500)

    # Video extensions that need ffmpeg frame extraction
    _VIDEO_EXTS = {
        "mp4","mkv","avi","mov","wmv","flv","webm","m4v","mpg","mpeg",
        "3gp","ts","mts","m2ts","vob","ogv","rm","rmvb",
    }

    def _route_thumbnail(self, params):
        rel = params.get("path", [""])[0]
        if not rel:
            return self.send_error_json("Missing 'path' parameter", 400)
        target = safe_path(rel)
        if target is None:
            return self.send_error_json("Invalid path", 403)
        if not target or not target.exists() or not target.is_file():
            return self.send_error_json("File not found", 404)

        try:
            max_w = min(int(params.get("w", ["300"])[0]), 600)
            max_h = min(int(params.get("h", ["300"])[0]), 600)
        except (ValueError, IndexError):
            max_w = max_h = 300

        ext = target.suffix.lstrip(".").lower()
        if ext in self._VIDEO_EXTS:
            self._serve_video_thumbnail(target, max_w, max_h)
        else:
            self._serve_image_thumbnail(target, max_w, max_h)

    def _serve_video_thumbnail(self, target: "Path", max_w: int, max_h: int):
        """Extract a JPEG frame from a video file using ffmpeg."""
        if not HAS_FFMPEG:
            return self.send_error_json(
                "ffmpeg not found - install it to enable video thumbnails", 501
            )
        import subprocess as _sp
        try:
            # Try at 5 s first; fall back to 0 s for short clips
            for seek in ("00:00:05", "00:00:01", "00:00:00"):
                cmd = [
                    FFMPEG_BIN,
                    "-loglevel", "error",
                    "-ss", seek,
                    "-i", str(target),
                    "-vframes", "1",
                    "-vf", f"scale='min({max_w},iw)':'min({max_h},ih)':force_original_aspect_ratio=decrease",
                    "-f", "image2",
                    "-vcodec", "mjpeg",
                    "pipe:1",
                ]
                result = _sp.run(
                    cmd,
                    stdout=_sp.PIPE,
                    stderr=_sp.PIPE,
                    timeout=15,
                )
                if result.returncode == 0 and result.stdout:
                    data = result.stdout
                    # Downscale large frames further when Pillow is available.
                    if HAS_PIL and len(data) > 300 * 1024:
                        try:
                            buf = BytesIO(data)
                            with PilImage.open(buf) as img:
                                img.thumbnail((max_w, max_h), PilImage.LANCZOS)
                                out = BytesIO()
                                img.save(out, format="JPEG", quality=70, optimize=True)
                                data = out.getvalue()
                        except Exception:
                            pass  # keep original ffmpeg output
                    try:
                        self.send_response(200)
                        self.send_header("Content-Type",   "image/jpeg")
                        self.send_header("Content-Length", str(len(data)))
                        self.send_header("Cache-Control",  "max-age=86400")
                        self._send_cors_headers()
                        self.end_headers()
                        self.wfile.write(data)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return
            # All seeks failed
            self.send_error_json("Could not extract video frame", 500)
        except _sp.TimeoutExpired:
            self.send_error_json("ffmpeg timed out", 504)
        except Exception as e:
            self.send_error_json(f"Video thumbnail error: {e}", 500)

    def _serve_image_thumbnail(self, target: "Path", max_w: int, max_h: int):
        """Resize an image file and return it as JPEG."""
        file_size = target.stat().st_size
        if file_size > 50 * 1024 * 1024:
            return self.send_error_json("File too large for thumbnail", 413)
        if not HAS_PIL:
            try:
                mime, _ = mimetypes.guess_type(str(target))
                self._serve_full(target, file_size, mime or "application/octet-stream")
            except Exception as e:
                self.send_error_json(f"Server error: {e}", 500)
            return
        try:
            with PilImage.open(target) as img:
                if img.width > 10000 or img.height > 10000:
                    return self.send_error_json("Image too large for thumbnail", 413)
                if img.mode not in ("RGB", "L"):
                    img = img.convert("RGB")
                img.thumbnail((max_w, max_h), PilImage.LANCZOS)
                buf = BytesIO()
                img.save(buf, format="JPEG", quality=75, optimize=True)
                data = buf.getvalue()
                if len(data) > 500 * 1024:
                    img.thumbnail((100, 100), PilImage.LANCZOS)
                    buf = BytesIO()
                    img.save(buf, format="JPEG", quality=60)
                    data = buf.getvalue()
            self.send_response(200)
            self.send_header("Content-Type",   "image/jpeg")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control",  "max-age=86400")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error_json(f"Thumbnail error: {e}", 500)

    def _route_art(self, params):
        rel = params.get("path", [""])[0]
        if not rel:
            return self.send_error_json("Missing 'path' parameter", 400)
        target = safe_path(rel)
        if target is None:
            return self.send_error_json("Invalid path", 403)
        if not target or not target.exists() or not target.is_file():
            return self.send_error_json("File not found", 404)
        result = extract_cover_from_mp3(target)
        if result:
            img_data, mime = result
            try:
                self.send_response(200)
                self.send_header("Content-Type",   mime)
                self.send_header("Content-Length", str(len(img_data)))
                self.send_header("Cache-Control",  "max-age=86400")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(img_data)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _route_upload_request_create(self):
        """Create an approval request or immediate upload grant for public uploads."""
        if not state.FEATURE_FLAGS.get("upload"):
            return self.send_error_json("Upload disabled", 403)
        if not _is_tunnel_request(self):
            token = state.issue_public_upload_grant("", 0, self.client_address[0], "/")
            return self.send_json({"status": "accepted", "upload_token": token})

        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_error_json("Invalid JSON body", 400)

        filename = str(payload.get("filename", "")).strip()
        try:
            size = int(payload.get("size", 0))
        except (TypeError, ValueError):
            size = 0
        if not filename or Path(filename).name != filename or filename in (".", ".."):
            return self.send_error_json("Invalid filename", 400)
        if size < 0:
            return self.send_error_json("Invalid size", 400)
        max_bytes = max(1, int(state.MAX_UPLOAD_SIZE_MB)) * 1024 * 1024
        if size > max_bytes:
            return self.send_error_json("Request body too large", 413)
        if state.ALLOWED_UPLOAD_EXTENSIONS:
            if Path(filename).suffix.lower() not in state.ALLOWED_UPLOAD_EXTENSIONS:
                return self.send_error_json("File type not allowed", 415)

        if state.PUBLIC_UPLOAD_MODE != "request":
            token = state.issue_public_upload_grant(
                filename, size, self.client_address[0], "/incoming"
            )
            return self.send_json({"status": "accepted", "upload_token": token})

        request = state.create_public_upload_request(
            filename, size, self.client_address[0], "/incoming"
        )
        self.send_json({
            "status": request["status"],
            "request_id": request["id"],
            "expires_at": request["expires_at"],
        }, 202)

    def _route_upload_request_status(self, params):
        request_id = params.get("id", [""])[0].strip()
        if not request_id:
            return self.send_error_json("Missing request id", 400)
        request = state.get_public_upload_request(request_id)
        if not request:
            return self.send_error_json("Request not found", 404)
        payload = {
            "status": request.get("status", "pending"),
            "request_id": request_id,
        }
        if request.get("status") == "accepted":
            payload["upload_token"] = request.get("token", "")
        self.send_json(payload)

    def _route_upload(self, params):
        """Receive a file upload and persist it under the configured directory."""
        if not state.FEATURE_FLAGS.get("upload"):
            return self.send_error_json("Upload disabled", 403)

        via_tunnel = _is_tunnel_request(self)
        role = self._public_role()
        if via_tunnel and role == "community":
            if not state.upload_allowed_for_ip(self.client_address[0]):
                state._record_write_activity("rate-limit", "public upload", None, self.client_address[0])
                return self.send_error_json("Upload rate limit exceeded", 429)

        folder_rel = "/incoming" if via_tunnel else params.get("path", ["/"])[0]
        filename = (
            params.get("filename", [""])[0]
            or unquote(self.headers.get("X-Filename", ""))
        ).strip()
        if not filename:
            return self.send_error_json("Missing filename", 400)
        if Path(filename).name != filename or filename in (".", ".."):
            return self.send_error_json("Invalid filename", 400)
        if via_tunnel and state.ALLOWED_UPLOAD_EXTENSIONS:
            if Path(filename).suffix.lower() not in state.ALLOWED_UPLOAD_EXTENSIONS:
                return self.send_error_json("File type not allowed", 415)

        upload_base = (
            (state.ROOT_DIR / "incoming") if via_tunnel
            else (state.ROOT_DIR / state.UPLOAD_DIRNAME)
        ).resolve()
        try:
            upload_base.relative_to(state.ROOT_DIR.resolve())
        except ValueError:
            return self.send_error_json("Invalid upload directory", 500)

        folder = upload_base if folder_rel in ("", "/") else self._safe_upload_folder(upload_base, folder_rel)
        if folder is None:
            return self.send_error_json("Invalid path", 403)
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return self.send_error_json(f"Upload directory unavailable: {e}", 500)
        if not folder.is_dir():
            return self.send_error_json("Target directory not found", 404)

        length = self._content_length()
        if length is None:
            return
        max_bytes = (
            max(1, int(state.MAX_UPLOAD_SIZE_MB)) * 1024 * 1024
            if via_tunnel else MAX_UPLOAD_BYTES
        )
        if length > max_bytes:
            return self.send_error_json("Request body too large", 413)
        if via_tunnel and state.PUBLIC_UPLOAD_MODE == "request":
            token = self.headers.get("X-Upload-Token", "").strip()
            if not state.consume_public_upload_grant(token, filename, length):
                return self.send_error_json("Upload request approval required", 403)

        overwrite = params.get("overwrite", ["0"])[0].lower() in ("1", "true", "yes")
        target = (folder / filename).resolve()
        try:
            target.relative_to(state.ROOT_DIR.resolve())
        except ValueError:
            return self.send_error_json("Invalid destination", 403)
        if target.exists() and not overwrite:
            target = self._unique_upload_path(target)

        try:
            rel_path = "/" + str(target.relative_to(state.ROOT_DIR)).replace("\\", "/")
            state._record_write_activity(
                "receiving", rel_path, length, self.client_address[0]
            )
            with open(target, "wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(self._CHUNK, remaining))
                    if not chunk:
                        raise OSError("Connection closed before upload completed")
                    f.write(chunk)
                    remaining -= len(chunk)
            self._notify_written_file(target)
            if via_tunnel:
                state.record_upload_for_ip(self.client_address[0])
                state.PUBLIC_UPLOAD_STATS["received"] += 1
            state._record_write_activity(
                "received", rel_path, target.stat().st_size, self.client_address[0]
            )
            self.send_json({
                "ok": True,
                "path": rel_path,
                "size": target.stat().st_size,
                "overwritten": overwrite,
            }, 201)
        except PermissionError:
            self.send_error_json("Permission denied", 403)
        except OSError as e:
            self.send_error_json(f"Upload failed: {e}", 500)

    def _route_document_get(self, params):
        if not state.FEATURE_FLAGS.get("document_edit"):
            return self.send_error_json("Document edit disabled", 403)
        target = self._editable_document_target(params)
        if target is None:
            return
        try:
            if target.stat().st_size > MAX_TEXT_EDIT_BYTES:
                return self.send_error_json("Document too large for inline edit", 413)
            raw = target.read_bytes()
            text = raw.decode("utf-8-sig")
            self.send_json({
                "path": "/" + str(target.relative_to(state.ROOT_DIR)).replace("\\", "/"),
                "name": target.name,
                "encoding": "utf-8",
                "content": text,
            })
        except UnicodeDecodeError:
            self.send_error_json("Document is not UTF-8 text", 415)
        except PermissionError:
            self.send_error_json("Permission denied", 403)
        except OSError as e:
            self.send_error_json(f"Read failed: {e}", 500)

    def _route_document_put(self, params):
        if not state.FEATURE_FLAGS.get("document_edit"):
            return self.send_error_json("Document edit disabled", 403)
        target = self._editable_document_target(params)
        if target is None:
            return
        body = self._read_body(MAX_TEXT_EDIT_BYTES, allow_empty=True)
        if body is None:
            return
        content_type = self.headers.get("Content-Type", "")
        try:
            if "application/json" in content_type:
                payload = json.loads(body.decode("utf-8"))
                text = str(payload.get("content", ""))
            else:
                text = body.decode("utf-8")
            with open(target, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            self._notify_written_file(target)
            state._record_write_activity(
                "edited",
                "/" + str(target.relative_to(state.ROOT_DIR)).replace("\\", "/"),
                target.stat().st_size,
                self.client_address[0],
            )
            self.send_json({
                "ok": True,
                "path": "/" + str(target.relative_to(state.ROOT_DIR)).replace("\\", "/"),
                "size": target.stat().st_size,
            })
        except UnicodeDecodeError:
            self.send_error_json("Document body must be UTF-8 text", 415)
        except json.JSONDecodeError:
            self.send_error_json("Invalid JSON body", 400)
        except PermissionError:
            self.send_error_json("Permission denied", 403)
        except OSError as e:
            self.send_error_json(f"Save failed: {e}", 500)

    def _editable_document_target(self, params) -> Path | None:
        rel = params.get("path", [""])[0]
        if not rel:
            self.send_error_json("Missing 'path' parameter", 400)
            return None
        target = safe_path(rel)
        if target is None:
            self.send_error_json("Invalid path", 403)
            return None
        if not target.exists():
            self.send_error_json("Document not found", 404)
            return None
        if not target.is_file():
            self.send_error_json("Not a file", 400)
            return None
        if target.suffix.lower() not in _TEXT_EDIT_EXTS:
            self.send_error_json(
                "Only text-like documents can be edited inline; use /upload to replace office files",
                415,
            )
            return None
        return target

    def _unique_upload_path(self, target: Path) -> Path:
        stem = target.stem
        suffix = target.suffix
        parent = target.parent
        for i in range(1, 10_000):
            candidate = parent / f"{stem} ({i}){suffix}"
            if not candidate.exists():
                return candidate
        return parent / f"{stem} ({os.getpid()}){suffix}"

    def _safe_upload_folder(self, upload_base: Path, rel_path: str) -> Path | None:
        clean = unquote(rel_path).lstrip("/\\")
        resolved = (upload_base / clean).resolve()
        try:
            resolved.relative_to(upload_base)
            return resolved
        except ValueError:
            return None

    def _notify_written_file(self, target: Path):
        try:
            from src.core.file_index import _file_index
            _file_index.add_file(target, state.ROOT_DIR)
            if state._ws_manager:
                rel = "/" + str(target.relative_to(state.ROOT_DIR)).replace("\\", "/")
                state._ws_manager.notify_file_change(rel)
        except Exception:
            pass

    # File-serving primitives

    _CHUNK = 8 * 1024 * 1024   # 8 MB write buffer

    def _serve_full(self, path: Path, size: int, mime: str):
        self.send_response(200)
        self.send_header("Content-Type",   mime)
        self.send_header("Content-Length", size)
        self.send_header("Accept-Ranges",  "bytes")
        self._send_cors_headers()
        # UTF-8 safe Content-Disposition
        try:
            ascii_name  = path.name.encode("ascii").decode("ascii")
            disposition = f'inline; filename="{ascii_name}"'
        except UnicodeEncodeError:
            disposition = f"inline; filename*=UTF-8''{quote(path.name)}"
        self.send_header("Content-Disposition", disposition)
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        self.end_headers()
        with open(path, "rb") as f:
            while chunk := f.read(self._CHUNK):
                try:
                    self.wfile.write(chunk)
                except BrokenPipeError:
                    break

    def _serve_range(self, path: Path, size: int, mime: str, range_header: str):
        try:
            byte_range = range_header.replace("bytes=", "")
            parts      = byte_range.split("-")
            start      = int(parts[0]) if parts[0] else 0
            end        = int(parts[1]) if parts[1] else size - 1
            end        = min(end, size - 1)
            length     = end - start + 1

            self.send_response(206)
            self.send_header("Content-Type",   mime)
            self.send_header("Content-Length", length)
            self.send_header("Content-Range",  f"bytes {start}-{end}/{size}")
            self.send_header("Accept-Ranges",  "bytes")
            self._send_cors_headers()
            try:
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            self.end_headers()

            with open(path, "rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(self._CHUNK, remaining))
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except BrokenPipeError:
                        break
                    remaining -= len(chunk)
        except (ValueError, IndexError):
            self._serve_full(path, size, mime)
        except (BrokenPipeError, ConnectionResetError):
            pass
