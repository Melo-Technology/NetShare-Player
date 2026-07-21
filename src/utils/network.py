"""Network, path-safety, and lightweight media metadata helpers."""

import mimetypes
import socket
import struct
from functools import lru_cache
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

import src.state as state


# Local IP enumeration

def get_local_ips() -> list[str]:
    """Return the address clients should use to reach this computer.

    The address selected by the system's default IPv4 route is preferred.  A
    hostname lookup on Windows also returns Hyper-V, WSL and VPN addresses,
    which produced valid-looking but unreachable QR codes for mobile clients.
    """
    primary_ip = None
    route_socket = None
    try:
        route_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # UDP connect selects a route without sending traffic to this address.
        route_socket.connect(("8.8.8.8", 80))
        candidate = route_socket.getsockname()[0]
        if _is_usable_ipv4(candidate):
            primary_ip = candidate
    except OSError:
        pass
    finally:
        if route_socket is not None:
            route_socket.close()

    if primary_ip:
        return [primary_ip]

    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if _is_usable_ipv4(ip) and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips or ["127.0.0.1"]


def _is_usable_ipv4(ip: str) -> bool:
    return (
        ":" not in ip
        and not ip.startswith("127.")
        and not ip.startswith("169.254.")
        and ip != "0.0.0.0"
    )


# Path safety

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


# File metadata

def file_info(path: Path, base: Path) -> dict:
    rel  = str(path.relative_to(base)).replace("\\", "/")
    stat = path.stat()
    info = {
        "name":     path.name,
        "path":     f"/{rel}",
        "is_dir":   path.is_dir(),
        "size":     stat.st_size if path.is_file() else None,
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
    }
    if path.is_file() and path.suffix.lower() == ".mp3":
        info.update(_cached_id3_metadata(str(path), stat.st_mtime_ns, stat.st_size))
    return info


@lru_cache(maxsize=4096)
def _cached_id3_metadata(path: str, _mtime_ns: int, _size: int) -> dict:
    return extract_id3_metadata(Path(path))


def _decode_id3_text(frame: bytes) -> str:
    if not frame:
        return ""
    encoding = frame[0]
    payload = frame[1:]
    codecs = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}
    try:
        return payload.decode(codecs.get(encoding, "utf-8"), errors="replace").strip("\x00 ")
    except (LookupError, UnicodeError):
        return ""


def extract_id3_metadata(file_path: Path) -> dict:
    """Extract common ID3v2 text frames without adding a runtime dependency."""
    wanted = {
        "TIT2": "title",
        "TPE1": "artist",
        "TPE2": "album_artist",
        "TALB": "album",
        "TCON": "genre",
        "TDRC": "year",
        "TYER": "year",
    }
    metadata: dict[str, str] = {}
    try:
        with file_path.open("rb") as stream:
            header = stream.read(10)
            if len(header) < 10 or header[:3] != b"ID3":
                return metadata
            version = header[3]
            tag_size = (
                (header[6] & 0x7F) << 21
                | (header[7] & 0x7F) << 14
                | (header[8] & 0x7F) << 7
                | (header[9] & 0x7F)
            )
            tag_data = stream.read(min(tag_size, 16 * 1024 * 1024))

        offset = 0
        while offset + 10 <= len(tag_data):
            frame_id = tag_data[offset:offset + 4].decode("ascii", errors="ignore")
            if not frame_id.strip("\x00"):
                break
            size_bytes = tag_data[offset + 4:offset + 8]
            frame_size = (
                ((size_bytes[0] & 0x7F) << 21)
                | ((size_bytes[1] & 0x7F) << 14)
                | ((size_bytes[2] & 0x7F) << 7)
                | (size_bytes[3] & 0x7F)
                if version >= 4
                else struct.unpack(">I", size_bytes)[0]
            )
            offset += 10
            if frame_size <= 0 or offset + frame_size > len(tag_data):
                break
            if frame_id in wanted:
                value = _decode_id3_text(tag_data[offset:offset + frame_size])
                if value:
                    metadata[wanted[frame_id]] = value
            offset += frame_size
    except (OSError, ValueError, struct.error):
        return {}

    if not metadata.get("artist") and metadata.get("album_artist"):
        metadata["artist"] = metadata["album_artist"]
    return metadata


# Cover art (ID3 APIC extractor)

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
