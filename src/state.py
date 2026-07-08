"""
Global runtime state for NetShare Server.

Mutable server settings, queues, feature flags, and singleton references live
here because the GUI, HTTP server, WebSocket server, and file index all need to
share the same live objects. Import this module as `src.state` so callers always
read the current value instead of a stale copy.
"""

import json
import os
import queue
import secrets
import socket
import threading
import time
import base64
import hashlib
import hmac
import struct
from pathlib import Path

try:
    import pyotp
except ImportError:
    class _FallbackTOTP:
        def __init__(self, secret: str, interval: int = 30, digits: int = 6):
            self.secret = secret
            self.interval = interval
            self.digits = digits

        def at(self, for_time: float) -> str:
            key = base64.b32decode(self.secret.upper() + "=" * ((8 - len(self.secret) % 8) % 8))
            counter = int(for_time // self.interval)
            msg = struct.pack(">Q", counter)
            digest = hmac.new(key, msg, hashlib.sha1).digest()
            offset = digest[-1] & 0x0F
            code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
            return str(code % (10 ** self.digits)).zfill(self.digits)

        def verify(self, otp: str, valid_window: int = 0) -> bool:
            now = time.time()
            for offset in range(-valid_window, valid_window + 1):
                if hmac.compare_digest(str(otp), self.at(now + offset * self.interval)):
                    return True
            return False

        def provisioning_uri(self, name: str, issuer_name: str = "") -> str:
            from urllib.parse import quote
            label = quote(f"{issuer_name}:{name}" if issuer_name else name)
            issuer = f"&issuer={quote(issuer_name)}" if issuer_name else ""
            return f"otpauth://totp/{label}?secret={self.secret}{issuer}"

    class _FallbackPyOTP:
        TOTP = _FallbackTOTP

        @staticmethod
        def random_base32(length: int = 32) -> str:
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            return "".join(secrets.choice(alphabet) for _ in range(length))

    pyotp = _FallbackPyOTP()

# Server / directory state

ROOT_DIR:        Path = Path.cwd()
SERVER_NAME:     str  = socket.gethostname()
LOCAL_PASSWORD:  str  = ""   # password for LAN clients
TUNNEL_PASSWORD: str  = ""   # password for public-tunnel clients
TUNNEL_ACTIVE:   bool = False
UPLOAD_DIRNAME:  str  = "NetShare Received"

# Persistent config

_CONFIG_DIR = (
    Path(os.environ["APPDATA"]) / "NetShare Player"
    if os.environ.get("APPDATA")
    else Path.home() / ".netshare-player"
)
CONFIG_PATH = _CONFIG_DIR / "server_config.json"
_FALLBACK_CONFIG_PATH = Path.cwd() / ".netshare_server_config.json"


def _load_config() -> dict:
    for path in (CONFIG_PATH, _FALLBACK_CONFIG_PATH):
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def _save_config():
    config_data = json.dumps({
        "totp_secret": TOTP_SECRET,
        "trusted_devices": TRUSTED_DEVICES,
        "community_password": COMMUNITY_PASSWORD,
        "admin_password": ADMIN_PASSWORD,
        "community_browse_root": COMMUNITY_BROWSE_ROOT,
        "community_download": COMMUNITY_DOWNLOAD,
        "community_upload": COMMUNITY_UPLOAD,
        "public_upload_mode": PUBLIC_UPLOAD_MODE,
        "max_uploads_per_hour": MAX_UPLOADS_PER_HOUR,
        "max_upload_size_mb": MAX_UPLOAD_SIZE_MB,
        "allowed_upload_extensions": sorted(ALLOWED_UPLOAD_EXTENSIONS),
    }, ensure_ascii=False, indent=2)
    try:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(config_data, encoding="utf-8")
    except OSError:
        try:
            _FALLBACK_CONFIG_PATH.write_text(config_data, encoding="utf-8")
        except OSError as e:
            print(f"CONFIG save failed: {e}")


_CONFIG = _load_config()

# Client write access

FEATURE_FLAGS: dict[str, bool] = {
    "upload": False,
    "document_edit": False,
    "write_pairing": False,
}

TOTP_SECRET: str = str(_CONFIG.get("totp_secret") or pyotp.random_base32())
TRUSTED_DEVICES: dict[str, float] = {
    str(k): float(v)
    for k, v in dict(_CONFIG.get("trusted_devices") or {}).items()
}

COMMUNITY_PASSWORD: str = str(_CONFIG.get("community_password") or "")
ADMIN_PASSWORD: str = str(_CONFIG.get("admin_password") or "")
COMMUNITY_BROWSE_ROOT: bool = bool(_CONFIG.get("community_browse_root", False))
COMMUNITY_DOWNLOAD: bool = bool(_CONFIG.get("community_download", True))
COMMUNITY_UPLOAD: bool = bool(_CONFIG.get("community_upload", True))
PUBLIC_UPLOAD_MODE: str = str(_CONFIG.get("public_upload_mode") or "direct")
UPLOAD_RATE_LIMITS: dict[str, list[float]] = {}
MAX_UPLOADS_PER_HOUR = int(_CONFIG.get("max_uploads_per_hour") or 10)
MAX_UPLOAD_SIZE_MB = int(_CONFIG.get("max_upload_size_mb") or 50)
ALLOWED_UPLOAD_EXTENSIONS: set[str] = set(_CONFIG.get("allowed_upload_extensions") or {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic",
    ".mp4", ".mov", ".mkv", ".avi", ".webm",
    ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg",
    ".txt", ".md", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz",
})
UPLOAD_RATE_LOCK = threading.RLock()
PUBLIC_UPLOAD_STATS = {
    "received": 0,
    "rate_limited_ips": set(),
}
UPLOAD_REQUEST_LOCK = threading.RLock()
PENDING_UPLOAD_REQUESTS: dict[str, dict] = {}
PUBLIC_UPLOAD_GRANTS: dict[str, dict] = {}
PUBLIC_UPLOAD_REQUEST_TTL_SECONDS = 2 * 60

_save_config()

WRITE_OTP:              str   = ""
WRITE_OTP_EXPIRES_AT:   float = 0.0
WRITE_OTP_TTL_SECONDS:  int   = 10 * 60
WRITE_TOKEN_TTL_SECONDS:int   = 60 * 60
WRITE_TOKENS:           dict[str, float] = {}
WRITE_AUTH_LOCK               = threading.RLock()

AUTH_RATE_LIMIT_MAX_ATTEMPTS = 8
AUTH_RATE_LIMIT_WINDOW_SECONDS = 5 * 60
AUTH_RATE_LIMITS: dict[str, list[float]] = {}
AUTH_RATE_LOCK = threading.RLock()


def verify_totp(code: str) -> bool:
    """Return True when *code* is a valid TOTP for this server."""
    clean = "".join(ch for ch in str(code).strip() if ch.isdigit())
    if len(clean) != 6:
        return False
    return bool(pyotp.TOTP(TOTP_SECRET).verify(clean, valid_window=1))


def register_device(device_id: str, code: str) -> bool:
    """Trust a device UUID after validating the current TOTP code."""
    clean_id = str(device_id).strip()
    if not clean_id or not verify_totp(code):
        return False
    with WRITE_AUTH_LOCK:
        TRUSTED_DEVICES[clean_id] = time.time()
        _save_config()
    return True


def is_trusted_device(device_id: str) -> bool:
    """Return True when a device ID has already been registered as trusted."""
    clean_id = str(device_id or "").strip()
    return bool(clean_id and clean_id in TRUSTED_DEVICES)


def revoke_device(device_id: str):
    """Remove a trusted device and persist the updated trust list."""
    clean_id = str(device_id or "").strip()
    if not clean_id:
        return
    with WRITE_AUTH_LOCK:
        TRUSTED_DEVICES.pop(clean_id, None)
        _save_config()


def upload_allowed_for_ip(ip: str) -> bool:
    now = time.time()
    cutoff = now - 60 * 60
    with UPLOAD_RATE_LOCK:
        timestamps = [ts for ts in UPLOAD_RATE_LIMITS.get(ip, []) if ts >= cutoff]
        UPLOAD_RATE_LIMITS[ip] = timestamps
        allowed = len(timestamps) < MAX_UPLOADS_PER_HOUR
        if not allowed:
            PUBLIC_UPLOAD_STATS["rate_limited_ips"].add(ip)
        return allowed


def record_upload_for_ip(ip: str):
    now = time.time()
    cutoff = now - 60 * 60
    with UPLOAD_RATE_LOCK:
        timestamps = [ts for ts in UPLOAD_RATE_LIMITS.get(ip, []) if ts >= cutoff]
        timestamps.append(now)
        UPLOAD_RATE_LIMITS[ip] = timestamps


def save_public_config():
    """Persist the latest public-upload settings to disk."""
    _save_config()


def create_public_upload_request(
    filename: str,
    size: int,
    client: str = "",
    folder: str = "/incoming",
) -> dict:
    """Create a pending public upload request and track it until it is accepted."""
    now = time.time()
    request_id = secrets.token_urlsafe(12)
    request = {
        "id": request_id,
        "filename": filename,
        "size": int(size),
        "client": client,
        "folder": folder,
        "status": "pending",
        "created_at": now,
        "expires_at": now + PUBLIC_UPLOAD_REQUEST_TTL_SECONDS,
        "token": "",
    }
    with UPLOAD_REQUEST_LOCK:
        PENDING_UPLOAD_REQUESTS[request_id] = request
    _record_write_activity("upload-request", filename, size, client, request_id)
    return request.copy()


def issue_public_upload_grant(
    filename: str,
    size: int,
    client: str = "",
    folder: str = "/incoming",
) -> str:
    token = secrets.token_urlsafe(24)
    with UPLOAD_REQUEST_LOCK:
        PUBLIC_UPLOAD_GRANTS[token] = {
            "filename": filename,
            "size": int(size),
            "client": client,
            "folder": folder,
            "expires_at": time.time() + PUBLIC_UPLOAD_REQUEST_TTL_SECONDS,
        }
    return token


def resolve_public_upload_request(request_id: str, accepted: bool) -> dict | None:
    """Accept or decline a pending public upload request and return the updated record."""
    with UPLOAD_REQUEST_LOCK:
        request = PENDING_UPLOAD_REQUESTS.get(request_id)
        if not request:
            return None
        if request.get("status") != "pending":
            return request.copy()
        request["status"] = "accepted" if accepted else "declined"
        if accepted:
            request["token"] = issue_public_upload_grant(
                request["filename"],
                request["size"],
                request.get("client", ""),
                request.get("folder", "/incoming"),
            )
        return request.copy()


def get_public_upload_request(request_id: str) -> dict | None:
    """Return a pending upload request, marking it expired when its TTL has elapsed."""
    now = time.time()
    with UPLOAD_REQUEST_LOCK:
        request = PENDING_UPLOAD_REQUESTS.get(request_id)
        if not request:
            return None
        if request.get("status") == "pending" and request.get("expires_at", 0) <= now:
            request["status"] = "expired"
        return request.copy()


def consume_public_upload_grant(token: str, filename: str, size: int) -> bool:
    now = time.time()
    with UPLOAD_REQUEST_LOCK:
        expired = [
            tok for tok, grant in PUBLIC_UPLOAD_GRANTS.items()
            if grant.get("expires_at", 0) <= now
        ]
        for tok in expired:
            PUBLIC_UPLOAD_GRANTS.pop(tok, None)
        grant = PUBLIC_UPLOAD_GRANTS.get(token)
        if not grant:
            return False
        if grant.get("filename") != filename or int(grant.get("size", -1)) != int(size):
            return False
        PUBLIC_UPLOAD_GRANTS.pop(token, None)
        return True


def reset_write_auth() -> str:
    """Create a fresh one-time code and clear old write tokens."""
    global WRITE_OTP, WRITE_OTP_EXPIRES_AT, WRITE_TOKENS
    with WRITE_AUTH_LOCK:
        WRITE_OTP = f"{secrets.randbelow(1_000_000):06d}"
        WRITE_OTP_EXPIRES_AT = time.time() + WRITE_OTP_TTL_SECONDS
        WRITE_TOKENS = {}
        return WRITE_OTP


def issue_write_token(otp: str) -> str | None:
    """Exchange the current OTP for a short-lived bearer token."""
    global WRITE_OTP, WRITE_OTP_EXPIRES_AT
    now = time.time()
    with WRITE_AUTH_LOCK:
        if not WRITE_OTP or now > WRITE_OTP_EXPIRES_AT or otp != WRITE_OTP:
            return None
        token = secrets.token_urlsafe(32)
        WRITE_TOKENS[token] = now + WRITE_TOKEN_TTL_SECONDS
        WRITE_OTP = ""
        WRITE_OTP_EXPIRES_AT = 0.0
        return token


def validate_write_token(token: str) -> bool:
    """Return True when a token exists and has not expired."""
    if not token:
        return False
    now = time.time()
    with WRITE_AUTH_LOCK:
        expired = [tok for tok, exp in WRITE_TOKENS.items() if exp <= now]
        for tok in expired:
            WRITE_TOKENS.pop(tok, None)
        return WRITE_TOKENS.get(token, 0.0) > now


def clear_write_auth():
    """Remove all temporary write-pairing credentials and one-time codes."""
    global WRITE_OTP, WRITE_OTP_EXPIRES_AT, WRITE_TOKENS
    with WRITE_AUTH_LOCK:
        WRITE_OTP = ""
        WRITE_OTP_EXPIRES_AT = 0.0
        WRITE_TOKENS = {}


def auth_attempt_allowed(key: str) -> bool:
    """Return False when too many failed auth attempts occurred recently."""
    now = time.time()
    cutoff = now - AUTH_RATE_LIMIT_WINDOW_SECONDS
    with AUTH_RATE_LOCK:
        attempts = [ts for ts in AUTH_RATE_LIMITS.get(key, []) if ts >= cutoff]
        AUTH_RATE_LIMITS[key] = attempts
        return len(attempts) < AUTH_RATE_LIMIT_MAX_ATTEMPTS


def record_auth_failure(key: str):
    """Record another failed authentication attempt for a request key."""
    now = time.time()
    cutoff = now - AUTH_RATE_LIMIT_WINDOW_SECONDS
    with AUTH_RATE_LOCK:
        attempts = [ts for ts in AUTH_RATE_LIMITS.get(key, []) if ts >= cutoff]
        attempts.append(now)
        AUTH_RATE_LIMITS[key] = attempts


def clear_auth_failures(key: str):
    """Reset the failed-attempt history for a request key after a successful auth."""
    with AUTH_RATE_LOCK:
        AUTH_RATE_LIMITS.pop(key, None)

# Log pipeline
# _log_callback is set to a no-op lambda while the server is running so that
# _emit() stops calling print(); the GUI drains _log_queue via a Tkinter timer.

_log_queue:    queue.Queue = queue.Queue()
_log_callback              = None        # set by App._start_server
_write_activity_queue: queue.Queue = queue.Queue()


def _emit(msg: str, kind: str = "info"):
    """Put a log entry on the queue; also print when no GUI is attached."""
    _log_queue.put((msg, kind))
    if not _log_callback:
        print(msg)


def _record_write_activity(
    action: str,
    path: str,
    size: int | None = None,
    client: str = "",
    request_id: str = "",
):
    """Queue an upload/edit event for the GUI activity panel."""
    _write_activity_queue.put({
        "action": action,
        "path": path,
        "size": size,
        "client": client,
        "request_id": request_id,
        "time": time.time(),
    })


# Runtime singletons (set/cleared by App)
# These are mutable references; always access via  state._ws_manager  etc.

_ws_manager  = None   # core.websocket_manager.WebSocketManager | None
