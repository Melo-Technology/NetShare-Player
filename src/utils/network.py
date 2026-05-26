"""
NetShare Player — Network / filesystem utilities
"""

import mimetypes
import socket
import struct
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

import src.state as state


# == Local IP enumeration =======================================================

def get_local_ips() -> list[str]:
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if (
                ":" not in ip
                and not ip.startswith("127.")
                and not ip.startswith("169.254.")
                and ip not in ips
            ):
                ips.append(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        if ip not in ips:
            ips.append(ip)
        s.close()
    except Exception:
        pass
    return ips or ["127.0.0.1"]


# == Path safety ================================================================

def safe_path(rel_path: str) -> Path | None:
    """
    Resolve a client-supplied relative path inside ROOT_DIR.
    Returns None if the resolved path escapes the root (path-traversal guard).
    """
    clean    = unquote(rel_path).lstrip("/\\")
    resolved = (state.ROOT_DIR / clean).resolve()
    try:
        resolved.relative_to(state.ROOT_DIR.resolve())
        return resolved
    except ValueError:
        return None


# == File metadata ==============================================================

def file_info(path: Path, base: Path) -> dict:
    rel  = str(path.relative_to(base)).replace("\\", "/")
    stat = path.stat()
    return {
        "name":     path.name,
        "path":     f"/{rel}",
        "is_dir":   path.is_dir(),
        "size":     stat.st_size if path.is_file() else None,
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
    }


# == Cover art (ID3 APIC extractor) ============================================

def extract_cover_from_mp3(file_path: Path) -> tuple[bytes, str] | None:
    """
    Parse the ID3v2 tag of an MP3 file and return (image_bytes, mime_type)
    for the first embedded APIC (cover art) frame, or None if not found.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(10)
        if len(header) < 10 or header[:3] != b"ID3":
            return None

        id3_version = header[3]
        tag_size = (
            (header[6] & 0x7F) << 21
            | (header[7] & 0x7F) << 14
            | (header[8] & 0x7F) << 7
            | (header[9] & 0x7F)
        )

        with open(file_path, "rb") as f:
            f.seek(10)
            tag_data = f.read(tag_size)

        i = 0
        while i + 10 <= len(tag_data):
            frame_id = tag_data[i:i+4].decode("latin-1", errors="ignore")
            if frame_id == "\x00\x00\x00\x00":
                break
            if id3_version >= 4:
                frame_size = (
                    (tag_data[i+4] & 0x7F) << 21
                    | (tag_data[i+5] & 0x7F) << 14
                    | (tag_data[i+6] & 0x7F) << 7
                    | (tag_data[i+7] & 0x7F)
                )
            else:
                frame_size = struct.unpack(">I", tag_data[i+4:i+8])[0]
            i += 10
            if frame_size <= 0 or i + frame_size > len(tag_data):
                break

            if frame_id == "APIC":
                frame = tag_data[i:i+frame_size]
                try:
                    encoding = frame[0]
                    mime_end = frame.index(b"\x00", 1)
                    mime     = frame[1:mime_end].decode("latin-1", errors="ignore").strip()
                    rest     = frame[mime_end+1:]
                    if encoding in (1, 2):
                        desc_end = 1
                        while desc_end + 1 < len(rest):
                            if rest[desc_end] == 0 and rest[desc_end+1] == 0:
                                desc_end += 2
                                break
                            desc_end += 2
                    else:
                        desc_end = rest.index(b"\x00", 1) + 1
                    img_data = rest[desc_end:]
                    if not mime or "/" not in mime:
                        mime = "image/jpeg"
                    if len(img_data) > 0:
                        return img_data, mime
                except Exception:
                    pass
            i += frame_size

    except Exception:
        pass
    return None
