"""
NetShare Player — HTTP request handler

NetShareHandler is a BaseHTTPRequestHandler subclass that serves all
API routes used by the Flutter mobile client:

    GET /ping         server info + auth mode
    GET /list         directory listing
    GET /search       file-index search
    GET /file         full / ranged file download
    GET /thumbnail    image thumbnail (Pillow)
    GET /art          MP3 cover-art extraction
"""

import json
import mimetypes
import socket
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


# == Tunnel detection ===========================================================

def _is_tunnel_request(handler) -> bool:
    """
    Return True when the request is forwarded through the public SSH tunnel.

    localhost.run connects back to 127.0.0.1, so the only reliable signal is
    the X-Tunnel: 1 header that the Flutter app sets when using the public URL.
    We only honour this header when TUNNEL_ACTIVE is True, preventing spoofing.
    """
    if not state.TUNNEL_ACTIVE:
        return False
    return handler.headers.get("X-Tunnel", "").strip() == "1"


# == HTTP handler ===============================================================

class NetShareHandler(BaseHTTPRequestHandler):

    # == Logging overrides ======================================================

    def log_message(self, fmt, *args):
        pass   # suppress default stderr output

    def log_request(self, code="-", size="-"):
        status = str(code)
        kind   = "error" if status[0] in ("4", "5") else "info"
        state._emit(
            f"{self.command:<8} {self.path}  →  {code}  [{self.client_address[0]}]",
            kind,
        )

    def log_error(self, fmt, *args):
        state._emit(f"ERROR  {fmt % args}", "error")

    # == Response helpers =======================================================

    def send_json(self, data, status=200):
        try:
            body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type",   "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_error_json(self, msg: str, status: int = 400):
        try:
            self.send_json({"error": msg}, status)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # == Auth ===================================================================

    def _check_password(self) -> bool:
        """
        Validate the X-Password header against the correct password for this
        request context (tunnel vs. LAN).  Empty password = open access.
        """
        via_tunnel = _is_tunnel_request(self)
        if via_tunnel:
            if not state.TUNNEL_PASSWORD:
                return True
            received = unquote(self.headers.get("X-Password", ""))
            return received == state.TUNNEL_PASSWORD
        else:
            if not state.LOCAL_PASSWORD:
                return True
            received = unquote(self.headers.get("X-Password", ""))
            return received == state.LOCAL_PASSWORD

    # == OPTIONS (CORS pre-flight) ==============================================

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    # == GET router =============================================================

    def do_GET(self):
        parsed   = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params   = parse_qs(parsed.query)

        if endpoint == "/ping":
            self._route_ping(params)
            return

        if not self._check_password():
            self.send_error_json("Unauthorized", 401)
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
        else:
            self.send_error_json("Unknown endpoint", 404)

    # == Route implementations ==================================================

    def _route_ping(self, params):
        from src.core.file_index import _file_index
        via_tunnel = _is_tunnel_request(self)
        ws_port    = None
        if state._ws_manager is not None:
            try:
                ws_port = int(self.server.server_address[1]) + 1
            except Exception:
                pass
        self.send_json({
            "name":               state.SERVER_NAME,
            "version":            VERSION,
            "root":               str(state.ROOT_DIR),
            "ws_port":            ws_port,
            "index_ready":        _file_index.ready,
            "index_total":        _file_index.total,
            "requires_password":  bool(state.TUNNEL_PASSWORD) if via_tunnel else bool(state.LOCAL_PASSWORD),
            "access_mode":        "tunnel" if via_tunnel else "local",
        })

    def _route_list(self, params):
        rel    = params.get("path", ["/"])[0]
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
        from src.core.file_index import _file_index
        if params.get("invalidate"):
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
                "ffmpeg not found — install it to enable video thumbnails", 501
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
                    # Optional: shrink further with PIL if available
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
                        self.send_header("Access-Control-Allow-Origin", "*")
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
            self.send_header("Access-Control-Allow-Origin", "*")
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
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(img_data)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    # == File-serving primitives ================================================

    _CHUNK = 8 * 1024 * 1024   # 8 MB write buffer

    def _serve_full(self, path: Path, size: int, mime: str):
        self.send_response(200)
        self.send_header("Content-Type",   mime)
        self.send_header("Content-Length", size)
        self.send_header("Accept-Ranges",  "bytes")
        self.send_header("Access-Control-Allow-Origin", "*")
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
            self.send_header("Access-Control-Allow-Origin", "*")
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