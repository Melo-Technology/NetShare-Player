"""
File serving: /file (full + Range downloads), /thumbnail, /art, /waveform,
plus the low-level streaming primitives (_serve_full, _serve_range, ETags)
shared by these routes and by /list (directory ETag).
"""

import hashlib
import mimetypes
import os
import socket
import subprocess
from io import BytesIO
from pathlib import Path
from urllib.parse import quote

import src.deps as deps
from src.deps import HAS_PIL
from src.core.thumbnail_cache import get_thumbnail_cache
from src.core.derived_media import derived_media_service
from src.core.content_policy import resolve_inbox_path
from src.core.shared_paths import resolve_shared_path
from src.utils.network import safe_path, extract_cover_from_mp3
from src.utils.network import extract_id3_metadata
from src.core.lyrics import lyrics_service, resolve_lyrics_query
from src.core.file_index import _file_index
import src.state as state

if HAS_PIL:
    from PIL import Image as PilImage

_CLIENT_DISCONNECT_ERRORS = (
    BrokenPipeError,
    ConnectionResetError,
    ConnectionAbortedError,
)

class FileRoutesMixin:

    def _route_lyrics(self, params):
        rel = params.get("path", [""])[0]
        if not rel:
            return self.send_error_json("Missing 'path' parameter", 400)
        cluster_path = self._parse_cluster_virtual_path(rel)
        if cluster_path:
            return self._route_cluster_derived(*cluster_path, "LYRICS", {})
        resolved = resolve_shared_path(rel, visible=True, require_file=True)
        target = resolved.path if resolved else None
        if target is None or not target.is_file():
            return self.send_error_json("Audio file not found", 404)
        if self._lock_status(rel)["locked"]:
            return self._send_premium_locked(self._lock_status(rel))
        metadata = extract_id3_metadata(target)
        analysis = _file_index.get_analysis(rel) or {}
        if not metadata.get("duration") and analysis.get("duration_seconds"):
            metadata["duration"] = analysis["duration_seconds"]
        query = resolve_lyrics_query(metadata, target.name)
        result = lyrics_service.lookup(**query)
        return self.send_json({"path": resolved.virtual_path, **result})

    # Video extensions that need ffmpeg frame extraction
    _VIDEO_EXTS = {
        "mp4","mkv","avi","mov","wmv","flv","webm","m4v","mpg","mpeg",
        "3gp","ts","mts","m2ts","vob","ogv","rm","rmvb",
    }

    _CHUNK = 8 * 1024 * 1024   # 8 MB write buffer

    def _route_file(self, params, *, cluster_web_session_id: str = ""):
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
        cluster_path = self._parse_cluster_virtual_path(rel)
        if cluster_path:
            return self._route_cluster_virtual_file(
                *cluster_path, web_session_id=cluster_web_session_id,
            )
        cloud_path = self._parse_cloud_virtual_path(rel)
        if cloud_path:
            provider_id, account_id, file_id = cloud_path
            return self._route_cloud_file({
                "provider": [provider_id],
                "account": [account_id],
                "id": [file_id],
            })
        inbox_prefix = "/@inbox/"
        is_inbox = rel.startswith(inbox_prefix)
        if is_inbox:
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            resolved_inbox = resolve_inbox_path(
                state.INBOX_DIR, rel[len(inbox_prefix):],
                visible=True, require_file=True,
            )
            target = resolved_inbox.path if resolved_inbox else None
        else:
            if resolve_shared_path(rel) is None:
                return self.send_error_json("Invalid path", 403)
            resolved = resolve_shared_path(
                rel, visible=True, require_file=True,
                allowed_paths=self._guest_allowed_paths(),
            )
            target = resolved.path if resolved else None
        if target is None or not target.exists():
            return self.send_error_json("File not found", 404)
        if not target.is_file():
            return self.send_error_json("Not a file", 400)
        lock = {"locked": False} if is_inbox else self._lock_status(rel)
        if lock["locked"]:
            return self.send_json({
                "error": "premium_locked",
                "folder_path": lock["folder_path"],
                "label": lock["label"],
                "price_note": lock["price_note"],
            }, 403)
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
                if_range = self.headers.get("If-Range", "").strip()
                if if_range and if_range != self._file_etag(target):
                    range_hdr = None
            if range_hdr:
                self._serve_range(target, file_size, mime, range_hdr)
            else:
                self._serve_full(target, file_size, mime)
        except PermissionError:
            self.send_error_json("Permission denied", 403)
        except Exception as error:
            state._emit(f"FILE serving failed ({type(error).__name__})", "error")
            self.send_error_json(
                "File unavailable", 500, code="storage.file_unavailable",
                domain="storage", support_code="STOR-02",
            )

    def _route_thumbnail(self, params):
        rel = params.get("path", [""])[0]
        if not rel:
            return self.send_error_json("Missing 'path' parameter", 400)
        cluster_path = self._parse_cluster_virtual_path(rel)
        if cluster_path:
            try:
                width = min(int(params.get("w", ["300"])[0]), 600)
                height = min(int(params.get("h", ["300"])[0]), 600)
            except (ValueError, IndexError):
                width = height = 300
            return self._route_cluster_derived(
                *cluster_path, "THUMBNAIL", {"width": width, "height": height},
            )
        resolved = resolve_shared_path(
            rel, visible=True, require_file=True,
            allowed_paths=self._guest_allowed_paths(),
        )
        target = resolved.path if resolved else None
        if target is None:
            return self.send_error_json("File not found", 404)
        lock = self._lock_status(rel)
        if lock["locked"]:
            return self._send_premium_locked(lock)

        try:
            max_w = min(int(params.get("w", ["300"])[0]), 600)
            max_h = min(int(params.get("h", ["300"])[0]), 600)
        except (ValueError, IndexError):
            max_w = max_h = 300

        try:
            resource = derived_media_service.thumbnail(target, max_w, max_h)
            if resource.status == 200:
                cache_key = get_thumbnail_cache().key(target, max_w, max_h)
                return self._send_thumbnail_data(resource.body, cache_key)
            return self._send_derived(resource)
        except (OSError, subprocess.SubprocessError) as error:
            state._emit(f"THUMBNAIL failed ({type(error).__name__})", "error")
            return self.send_error_json(
                "Thumbnail unavailable", 500, code="streaming.thumbnail_unavailable",
                domain="streaming", support_code="STRM-02",
            )

    def _route_waveform(self, params):
        rel = params.get("path", [""])[0]
        if not rel:
            return self.send_error_json("Missing 'path' parameter", 400)
        cluster_path = self._parse_cluster_virtual_path(rel)
        if cluster_path:
            try:
                samples = max(32, min(int(params.get("samples", ["160"])[0]), 4096))
            except (TypeError, ValueError, IndexError):
                samples = 160
            return self._route_cluster_derived(
                *cluster_path, "WAVEFORM", {"samples": samples},
            )
        resolved = resolve_shared_path(
            rel, visible=True, require_file=True,
            allowed_paths=self._guest_allowed_paths(),
        )
        target = resolved.path if resolved else None
        if target is None:
            return self.send_error_json("File not found", 404)
        lock = self._lock_status(rel)
        if lock["locked"]:
            return self._send_premium_locked(lock)
        try:
            samples = int(params.get("samples", ["160"])[0])
        except (TypeError, ValueError, IndexError):
            samples = 160
        try:
            resource = derived_media_service.waveform(rel, target, samples)
            self._send_derived(resource)
        except RuntimeError as error:
            status = 501 if not deps.HAS_FFMPEG else 422
            state._emit(f"WAVEFORM unavailable ({type(error).__name__})", "error")
            self.send_error_json(
                "Waveform unavailable", status, code="streaming.waveform_unavailable",
                domain="streaming", support_code="STRM-03",
            )
        except (OSError, subprocess.SubprocessError) as error:
            state._emit(f"WAVEFORM failed ({type(error).__name__})", "error")
            self.send_error_json(
                "Waveform unavailable", 500, code="streaming.waveform_unavailable",
                domain="streaming", support_code="STRM-03",
            )

    def _route_art(self, params):
        rel = params.get("path", [""])[0]
        if not rel:
            return self.send_error_json("Missing 'path' parameter", 400)
        cluster_path = self._parse_cluster_virtual_path(rel)
        if cluster_path:
            return self._route_cluster_derived(*cluster_path, "ART", {})
        resolved = resolve_shared_path(
            rel, visible=True, require_file=True,
            allowed_paths=self._guest_allowed_paths(),
        )
        target = resolved.path if resolved else None
        if target is None:
            return self.send_error_json("File not found", 404)
        lock = self._lock_status(rel)
        if lock["locked"]:
            return self._send_premium_locked(lock)
        try:
            self._send_derived(derived_media_service.artwork(target))
        except _CLIENT_DISCONNECT_ERRORS:
            pass

    def _send_derived(self, resource):
        self.send_response(resource.status)
        self.send_header("Content-Type", resource.mime)
        self.send_header("Content-Length", len(resource.body))
        self.send_header("Cache-Control", "private, max-age=86400" if resource.status == 200 else "no-store")
        self._send_cors_headers()
        self.end_headers()
        if resource.body:
            self.wfile.write(resource.body)

    # Thumbnail helpers

    def _send_thumbnail_data(self, data: bytes, cache_key: str):
        etag = f'"{cache_key}"'
        if self.headers.get("If-None-Match", "").strip() == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "private, max-age=86400")
            self._send_cors_headers()
            self.end_headers()
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "private, max-age=86400")
            self.send_header("ETag", etag)
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(data)
        except _CLIENT_DISCONNECT_ERRORS:
            pass

    def _serve_image_thumbnail(
        self, target: "Path", max_w: int, max_h: int, cache_key: str
    ):
        """Resize an image file and return it as JPEG."""
        file_size = target.stat().st_size
        if file_size > 50 * 1024 * 1024:
            return self.send_error_json("File too large for thumbnail", 413)
        if not HAS_PIL:
            return self.send_error_json(
                "Pillow not found - install it to enable image thumbnails", 501
            )
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
            cache = get_thumbnail_cache()
            if len(data) > cache.max_entry_bytes:
                return self.send_error_json("Thumbnail too large", 413)
            cache.put(cache_key, data)
            self._send_thumbnail_data(data, cache_key)
        except _CLIENT_DISCONNECT_ERRORS:
            pass
        except Exception as error:
            state._emit(f"THUMBNAIL failed ({type(error).__name__})", "error")
            self.send_error_json(
                "Thumbnail unavailable", 500, code="streaming.thumbnail_unavailable",
                domain="streaming", support_code="STRM-02",
            )

    # Streaming primitives (also used by BrowseRoutesMixin for the /list ETag)

    @staticmethod
    def _file_etag(path: Path) -> str:
        stat = path.stat()
        value = f"{path.resolve()}\0{stat.st_size}\0{stat.st_mtime_ns}"
        return f'"{hashlib.sha256(value.encode("utf-8")).hexdigest()}"'

    @staticmethod
    def _directory_etag(path: Path) -> str:
        """Shallow O(N) validator without reading any file contents."""
        count = 0
        highest_mtime_ns = 0
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    stat = entry.stat(follow_symlinks=False)
                except (PermissionError, FileNotFoundError, OSError):
                    continue
                count += 1
                highest_mtime_ns = max(highest_mtime_ns, stat.st_mtime_ns)
        value = f"{path.resolve()}\0{count}\0{highest_mtime_ns}"
        return f'"{hashlib.sha256(value.encode("utf-8")).hexdigest()}"'

    def _serve_full(self, path: Path, size: int, mime: str):
        if mime.startswith("video/"):
            import src.state as state
            state._emit(
                f"VIDEO 200 file={path.name!r} size={size} mime={mime} "
                f"range={self.headers.get('Range')!r}",
                "info",
            )
        self.send_response(200)
        self.send_header("Content-Type",   mime)
        self.send_header("Content-Length", size)
        self.send_header("Accept-Ranges",  "bytes")
        self.send_header("ETag", self._file_etag(path))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag, Content-Disposition")
        self._send_cors_headers()
        # UTF-8 safe Content-Disposition
        try:
            ascii_name  = path.name.encode("ascii").decode("ascii")
            disposition = f'{"attachment" if getattr(self, "_download_attachment", False) else "inline"}; filename="{ascii_name}"'
        except UnicodeEncodeError:
            mode = "attachment" if getattr(self, "_download_attachment", False) else "inline"
            disposition = f"{mode}; filename*=UTF-8''{quote(path.name)}"
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
                except _CLIENT_DISCONNECT_ERRORS:
                    break

    def _serve_range(self, path: Path, size: int, mime: str, range_header: str):
        import src.state as state
        try:
            if not range_header.startswith("bytes=") or "," in range_header:
                raise ValueError("unsupported range syntax")
            byte_range = range_header[6:].strip()
            parts = byte_range.split("-", 1)
            if len(parts) != 2 or not any(parts):
                raise ValueError("invalid byte range")

            if not parts[0]:
                # RFC 9110 suffix range: bytes=-N means the final N bytes.
                suffix_length = int(parts[1])
                if suffix_length <= 0:
                    raise ValueError("invalid suffix length")
                start = max(0, size - suffix_length)
                end = size - 1
            else:
                start = int(parts[0])
                end = int(parts[1]) if parts[1] else size - 1
                end = min(end, size - 1)

            if start < 0 or start >= size or end < start:
                raise ValueError("unsatisfiable byte range")
            length     = end - start + 1

            if mime.startswith("video/"):
                state._emit(
                    f"VIDEO 206 file={path.name!r} size={size} mime={mime} "
                    f"range={range_header!r} content-range='bytes {start}-{end}/{size}' "
                    f"length={length}",
                    "info",
                )

            self.send_response(206)
            self.send_header("Content-Type",   mime)
            self.send_header("Content-Length", length)
            self.send_header("Content-Range",  f"bytes {start}-{end}/{size}")
            self.send_header("Accept-Ranges",  "bytes")
            self.send_header("ETag", self._file_etag(path))
            self.send_header("Cache-Control", "private, no-store")
            self.send_header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag, Content-Disposition")
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
                    except _CLIENT_DISCONNECT_ERRORS:
                        break
                    remaining -= len(chunk)
        except (ValueError, IndexError) as exc:
            if mime.startswith("video/"):
                state._emit(
                    f"VIDEO 416 file={path.name!r} size={size} mime={mime} "
                    f"range={range_header!r} reason={exc}",
                    "error",
                )
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{size}")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", self._file_etag(path))
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "private, no-store")
            self._send_cors_headers()
            self.end_headers()
        except _CLIENT_DISCONNECT_ERRORS:
            pass
