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
import sqlite3
import socket
import threading
import time
import base64
import hashlib
import hmac
import struct
import uuid
from pathlib import Path

from src.core.shared_roots import PRIMARY_ROOT_SLOT, SharedRoot, normalize_shared_roots
from src.core.password_credentials import hash_password, verify_password
from src.core.web_sessions import WebSessionStore
from src.core.web_download_tickets import WebDownloadTicketStore
from src.core.web_media_grants import WebMediaGrantStore
from src.core.web_rate_limits import WebRateLimiter

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

        def now(self) -> str:
            """Match pyotp.TOTP.now() when the optional dependency is absent."""
            return self.at(time.time())

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
SHARED_ROOTS: tuple[SharedRoot, ...] = (SharedRoot(PRIMARY_ROOT_SLOT, ROOT_DIR),)
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
PROTECTED_CONFIG_PATH = _CONFIG_DIR / "protected_state.nsv"
INBOX_DIR = _CONFIG_DIR / "inbox"
INBOX_HISTORY_PATH = _CONFIG_DIR / "inbox_history.json"
USER_METADATA_PATH = _CONFIG_DIR / "user_metadata.json"
GUEST_PROFILES_PATH = _CONFIG_DIR / "guest_profiles.json"
WEB_SESSIONS_PATH = _CONFIG_DIR / "web_sessions.db"
_FALLBACK_CONFIG_PATH = Path.cwd() / ".netshare_server_config.json"
CONFIG_PREEXISTED_AT_BOOT = CONFIG_PATH.exists() or _FALLBACK_CONFIG_PATH.exists()

# Secrets and sensitive user metadata are moved out of server_config.json once
# the Data Vault is configured.  server_id and shared_roots intentionally stay
# in the bootstrap document: they are required to identify the server and show
# the configured roots before a password-mode vault is unlocked.
_PROTECTED_CONFIG_FIELDS = (
    "totp_secret",
    "trusted_devices",
    "community_password",
    "admin_password",
    "community_password_credential",
    "admin_password_credential",
    "web_password_credential",
    "local_password",
    "local_password_saved_at",
    "folder_share_history",
    "folder_pair_history",
    "hidden_paths",
)
_DATA_VAULT_BOOT_ERROR: str = ""


def _load_config() -> dict:
    for path in (CONFIG_PATH, _FALLBACK_CONFIG_PATH):
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def _atomic_write_text(path: Path, content: str) -> None:
    """Replace a configuration file atomically in its destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _merge_protected_config(config: dict) -> dict:
    """Best-effort boot unlock and merge of the encrypted config sidecar.

    OS-protected vaults unlock transparently. Password vaults unlock only when
    the user explicitly chose Remember on this Windows account. A locked vault
    leaves sensitive globals empty until the Settings unlock flow reloads them.
    """
    global _DATA_VAULT_BOOT_ERROR
    try:
        from src.core.data_vault import get_data_vault
        vault = get_data_vault(_CONFIG_DIR)
        if not vault.configured:
            return dict(config)
        if not vault.unlocked:
            status = vault.status()
            if status.mode == "os":
                vault.unlock_os()
            elif status.mode == "password":
                vault.try_unlock_remembered()
        if not vault.unlocked or not PROTECTED_CONFIG_PATH.exists():
            return dict(config)
        protected = vault.decrypt_json(PROTECTED_CONFIG_PATH, purpose="server-protected-config")
        if not isinstance(protected, dict):
            raise ValueError("protected config payload must be an object")
        values = protected.get("values", protected)
        if not isinstance(values, dict):
            raise ValueError("protected config values must be an object")
        merged = dict(config)
        for key in _PROTECTED_CONFIG_FIELDS:
            if key in values:
                merged[key] = values[key]
        _DATA_VAULT_BOOT_ERROR = ""
        return merged
    except Exception as exc:
        # The desktop must still be able to open Settings so the user can use
        # password/recovery unlock. Starting the file server is blocked later.
        _DATA_VAULT_BOOT_ERROR = f"{type(exc).__name__}: {exc}"
        return dict(config)


def _migrate_password_credentials(config: dict) -> dict:
    """Hash legacy public passwords before removing their clear-text fields."""
    migrated = dict(config)
    for legacy, credential in (
        ("admin_password", "admin_password_credential"),
        ("community_password", "community_password_credential"),
    ):
        plaintext = str(migrated.get(legacy) or "")
        if plaintext and not migrated.get(credential):
            candidate = hash_password(plaintext)
            if not verify_password(plaintext, candidate):
                raise RuntimeError("password credential migration verification failed")
            migrated[credential] = candidate
        if migrated.get(credential):
            migrated.pop(legacy, None)
    return migrated


def _save_config():
    values = {
        "totp_secret": TOTP_SECRET,
        "server_id": SERVER_ID,
        "trusted_devices": TRUSTED_DEVICES,
        "community_password_credential": COMMUNITY_PASSWORD_CREDENTIAL,
        "admin_password_credential": ADMIN_PASSWORD_CREDENTIAL,
        "web_password_credential": WEB_PASSWORD_CREDENTIAL,
        "web_access_enabled": WEB_ACCESS_ENABLED,
        "web_credential_generation": WEB_CREDENTIAL_GENERATION,
        "web_allowed_origins": list(WEB_ALLOWED_ORIGINS),
        "community_browse_root": COMMUNITY_BROWSE_ROOT,
        "community_download": COMMUNITY_DOWNLOAD,
        "community_upload": COMMUNITY_UPLOAD,
        "public_upload_mode": PUBLIC_UPLOAD_MODE,
        "max_uploads_per_hour": MAX_UPLOADS_PER_HOUR,
        "max_upload_size_mb": MAX_UPLOAD_SIZE_MB,
        "allowed_upload_extensions": sorted(ALLOWED_UPLOAD_EXTENSIONS),
        "local_password": SAVED_LOCAL_PASSWORD,
        "local_password_saved_at": LOCAL_PASSWORD_SAVED_AT,
        "password_reminder_days": PASSWORD_REMINDER_DAYS,
        "folder_share_history": FOLDER_SHARE_HISTORY,
        "folder_pair_history": FOLDER_PAIR_HISTORY,
        "shared_roots": [root.to_json() for root in SHARED_ROOTS],
        "hidden_paths": HIDDEN_PATHS,
        "external_tunnel_trusted_header": EXTERNAL_TUNNEL_TRUSTED_HEADER,
        "external_tunnel_trusted_proxies": list(EXTERNAL_TUNNEL_TRUSTED_PROXIES),
        "cluster_role": CLUSTER_ROLE,
        "cluster_node_created_at": CLUSTER_NODE_CREATED_AT,
        "show_advanced_settings": SHOW_ADVANCED_SETTINGS,
        "data_vault_prompt_state": DATA_VAULT_PROMPT_STATE,
        "data_vault_prompt_context": DATA_VAULT_PROMPT_CONTEXT,
        "keep_awake_enabled": KEEP_AWAKE_ENABLED,
        "security_monitor": SECURITY_MONITOR_CONFIG,
        "theme": THEME,
        "language": LANGUAGE,
        "text_size": TEXT_SIZE,
        "ffmpeg_path": FFMPEG_PATH,
        "performance_preset": PERFORMANCE_PRESET,
        "index_workers": INDEX_WORKERS,
        "analysis_workers": ANALYSIS_WORKERS,
        "gpu_encoder_preference": GPU_ENCODER_PREFERENCE,
        "log_buffer_lines": LOG_BUFFER_LINES,
    }

    try:
        from src.core.data_vault import get_data_vault
        vault = get_data_vault(_CONFIG_DIR)
        if vault.configured:
            if vault.unlocked:
                protected = {key: values.get(key) for key in _PROTECTED_CONFIG_FIELDS}
                vault.encrypt_json(
                    PROTECTED_CONFIG_PATH,
                    {"version": 1, "values": protected},
                    purpose="server-protected-config",
                )
            # Never write sensitive values back to plaintext merely because a
            # password-mode vault happens to be locked at this instant.
            for key in _PROTECTED_CONFIG_FIELDS:
                values.pop(key, None)
    except Exception:
        # If the vault is configured, a failure to protect data must not cause
        # a plaintext fallback. Public/non-secret settings can still persist.
        try:
            from src.core.data_vault import get_data_vault
            if get_data_vault(_CONFIG_DIR).configured:
                for key in _PROTECTED_CONFIG_FIELDS:
                    values.pop(key, None)
        except Exception:
            pass

    config_data = json.dumps(values, ensure_ascii=False, indent=2)
    try:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(CONFIG_PATH, config_data)
    except OSError:
        try:
            _atomic_write_text(_FALLBACK_CONFIG_PATH, config_data)
        except OSError:
            print("CONFIG save failed")


_CONFIG = _load_config()
try:
    _MIGRATED_CONFIG = _migrate_password_credentials(_CONFIG)
except (TypeError, ValueError, RuntimeError):
    # Keep the original in-memory configuration usable if migration cannot be
    # proven correct; never replace it with a partially migrated document.
    _MIGRATED_CONFIG = _CONFIG
if _MIGRATED_CONFIG != _CONFIG:
    try:
        _atomic_write_text(CONFIG_PATH, json.dumps(_MIGRATED_CONFIG, ensure_ascii=False, indent=2))
        _CONFIG = _MIGRATED_CONFIG
    except OSError:
        pass

_CONFIG = _merge_protected_config(_CONFIG)

# External reverse-proxy tunnel detection is deliberately disabled by default.
# Operators using an OS-managed cloudflared tunnel may opt in by setting
# "external_tunnel_trusted_header" to "CF-Ray" in server_config.json. The
# origin connection must also come from one of these explicitly trusted proxy
# networks; keeping cloudflared's ingress service on loopback is recommended.
EXTERNAL_TUNNEL_TRUSTED_HEADER: str = str(
    _CONFIG.get("external_tunnel_trusted_header") or ""
).strip()
EXTERNAL_TUNNEL_TRUSTED_PROXIES: tuple[str, ...] = tuple(
    str(value).strip()
    for value in (
        _CONFIG.get("external_tunnel_trusted_proxies")
        or ("127.0.0.1/32", "::1/128")
    )
    if str(value).strip()
)

# Client write access

FEATURE_FLAGS: dict[str, bool] = {
    "upload": False,
    "document_edit": False,
    "write_pairing": False,
    "cluster": False,
}
CLUSTER_ROLE: str = str(_CONFIG.get("cluster_role") or "standalone")
if CLUSTER_ROLE not in ("standalone", "auto", "master", "slave"):
    CLUSTER_ROLE = "standalone"
CLUSTER_NODE_CREATED_AT: float = float(_CONFIG.get("cluster_node_created_at") or time.time())
SHOW_ADVANCED_SETTINGS: bool = bool(_CONFIG.get("show_advanced_settings", True))
_DATA_VAULT_PROMPT_STATES = {"never_configured", "offered", "deferred", "configured"}
DATA_VAULT_PROMPT_STATE: str = str(_CONFIG.get("data_vault_prompt_state") or "never_configured")
if DATA_VAULT_PROMPT_STATE not in _DATA_VAULT_PROMPT_STATES:
    DATA_VAULT_PROMPT_STATE = "never_configured"
DATA_VAULT_PROMPT_CONTEXT: str = str(_CONFIG.get("data_vault_prompt_context") or ("update" if CONFIG_PREEXISTED_AT_BOOT else "first_run"))
if DATA_VAULT_PROMPT_CONTEXT not in {"first_run", "update"}:
    DATA_VAULT_PROMPT_CONTEXT = "update" if CONFIG_PREEXISTED_AT_BOOT else "first_run"
KEEP_AWAKE_ENABLED: bool = bool(_CONFIG.get("keep_awake_enabled", False))

_SECURITY_MONITOR_DEFAULTS = {
    "enabled": True,
    "notify": False,
    "block_mode": "temporary",
    "auth_failures": 8,
    "auth_window_seconds": 300,
    "block_seconds": 900,
    "burst_requests": 240,
    "burst_window_seconds": 60,
    "route_misses": 20,
    "route_window_seconds": 60,
}

def _normalized_security_monitor_config(raw) -> dict:
    value = dict(_SECURITY_MONITOR_DEFAULTS)
    if isinstance(raw, dict):
        value.update(raw)
    value["enabled"] = bool(value.get("enabled", True))
    value["notify"] = bool(value.get("notify", False))
    mode = str(value.get("block_mode") or "temporary").strip().lower()
    value["block_mode"] = mode if mode in {"monitor", "temporary", "permanent"} else "temporary"
    bounds = {
        "auth_failures": (2, 100),
        "auth_window_seconds": (10, 86400),
        "block_seconds": (30, 604800),
        "burst_requests": (30, 10000),
        "burst_window_seconds": (5, 3600),
        "route_misses": (3, 1000),
        "route_window_seconds": (5, 3600),
    }
    for key, (minimum, maximum) in bounds.items():
        try:
            parsed = int(value.get(key, _SECURITY_MONITOR_DEFAULTS[key]))
        except (TypeError, ValueError):
            parsed = int(_SECURITY_MONITOR_DEFAULTS[key])
        value[key] = max(minimum, min(maximum, parsed))
    return value

SECURITY_MONITOR_CONFIG: dict = _normalized_security_monitor_config(_CONFIG.get("security_monitor"))
THEME: str = str(_CONFIG.get("theme") or "system").lower()
if THEME not in ("system", "dark", "light"):
    THEME = "system"
LANGUAGE: str = str(_CONFIG.get("language") or "system").lower()
TEXT_SIZE: str = str(_CONFIG.get("text_size") or "small").lower()
if TEXT_SIZE not in ("small", "normal", "large"):
    TEXT_SIZE = "small"
FFMPEG_PATH: str = str(_CONFIG.get("ffmpeg_path") or "").strip()
PERFORMANCE_PRESET: str = str(_CONFIG.get("performance_preset") or "").strip().lower()
if PERFORMANCE_PRESET not in ("", "economy", "balanced_light", "balanced", "performance"):
    PERFORMANCE_PRESET = ""
INDEX_WORKERS = _CONFIG.get("index_workers")
ANALYSIS_WORKERS = _CONFIG.get("analysis_workers")
GPU_ENCODER_PREFERENCE: str = str(
    _CONFIG.get("gpu_encoder_preference") or "auto"
).strip().lower()
if GPU_ENCODER_PREFERENCE not in (
    "auto", "cpu", "gpu", "nvenc", "qsv", "amf", "videotoolbox",
):
    GPU_ENCODER_PREFERENCE = "auto"
from src.core.bounded_logs import clamp_log_buffer_lines
LOG_BUFFER_LINES: int = clamp_log_buffer_lines(_CONFIG.get("log_buffer_lines"))

TOTP_SECRET: str = str(_CONFIG.get("totp_secret") or pyotp.random_base32())
SERVER_ID: str = str(_CONFIG.get("server_id") or uuid.uuid4())
TRUSTED_DEVICES: dict[str, object] = {
    str(k): v
    for k, v in dict(_CONFIG.get("trusted_devices") or {}).items()
}

COMMUNITY_PASSWORD: str = str(_CONFIG.get("community_password") or "")
ADMIN_PASSWORD: str = str(_CONFIG.get("admin_password") or "")
COMMUNITY_PASSWORD_CREDENTIAL: str = str(_CONFIG.get("community_password_credential") or "")
ADMIN_PASSWORD_CREDENTIAL: str = str(_CONFIG.get("admin_password_credential") or "")
WEB_PASSWORD_CREDENTIAL: str = str(_CONFIG.get("web_password_credential") or "")
WEB_ACCESS_ENABLED: bool = bool(_CONFIG.get("web_access_enabled", False))
WEB_CREDENTIAL_GENERATION: int = max(1, int(_CONFIG.get("web_credential_generation") or 1))
try:
    WEB_SESSION_STORE = WebSessionStore(
        WEB_SESSIONS_PATH, generation=lambda: WEB_CREDENTIAL_GENERATION
    )
except (OSError, sqlite3.Error):
    # Match configuration persistence: restricted/service accounts may not be
    # able to create the roaming profile directory, so keep a durable fallback
    # beside the process working directory instead of preventing startup.
    WEB_SESSIONS_PATH = Path.cwd() / ".netshare_web_sessions.db"
    WEB_SESSION_STORE = WebSessionStore(
        WEB_SESSIONS_PATH, generation=lambda: WEB_CREDENTIAL_GENERATION
    )
WEB_DOWNLOAD_TICKET_STORE = WebDownloadTicketStore()
WEB_MEDIA_GRANT_STORE = WebMediaGrantStore()
WEB_RATE_LIMITER = WebRateLimiter()
WEB_ALLOWED_ORIGINS: tuple[str, ...] = tuple(
    dict.fromkeys([
        "https://web.netshareplayer.com",
        "https://web-staging.netshareplayer.com",
        *[
            str(origin).strip().rstrip("/")
            for origin in list(_CONFIG.get("web_allowed_origins") or [])
            if str(origin).strip().lower().startswith("https://")
        ],
    ])
)
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
SAVED_LOCAL_PASSWORD = str(_CONFIG.get("local_password") or "")
LOCAL_PASSWORD = SAVED_LOCAL_PASSWORD
LOCAL_PASSWORD_SAVED_AT = float(_CONFIG.get("local_password_saved_at") or 0.0)
PASSWORD_REMINDER_DAYS = max(1, int(_CONFIG.get("password_reminder_days") or 7))
FOLDER_SHARE_HISTORY: list[dict] = [
    {
        "path": str(item.get("path") or ""),
        "share_count": max(1, int(item.get("share_count") or 1)),
        "last_shared_at": float(item.get("last_shared_at") or 0.0),
    }
    for item in list(_CONFIG.get("folder_share_history") or [])
    if isinstance(item, dict) and item.get("path")
]
FOLDER_PAIR_HISTORY: list[dict] = [
    {
        "paths": [str(path) for path in item.get("paths", [])[:2]],
        "share_count": max(1, int(item.get("share_count") or 1)),
        "last_shared_at": float(item.get("last_shared_at") or 0.0),
    }
    for item in list(_CONFIG.get("folder_pair_history") or [])
    if isinstance(item, dict) and len(item.get("paths") or []) == 2
]
_configured_root_paths = [
    str(item.get("path") or "")
    for item in list(_CONFIG.get("shared_roots") or [])
    if isinstance(item, dict) and item.get("path")
]
try:
    SHARED_ROOTS = normalize_shared_roots(_configured_root_paths or [ROOT_DIR])
except ValueError:
    # A malformed or pre-release multiroot config must not prevent startup.
    SHARED_ROOTS = normalize_shared_roots([(_configured_root_paths or [ROOT_DIR])[0]])
ROOT_DIR = SHARED_ROOTS[0].path
HIDDEN_PATHS: dict[str, list[str]] = {
    slot: sorted({
        "/" + str(path).strip().replace("\\", "/").strip("/")
        for path in list(dict(_CONFIG.get("hidden_paths") or {}).get(slot) or [])
        if str(path).strip().strip("/")
    })
    for slot in ("slot-1", "slot-2")
}
UPLOAD_RATE_LOCK = threading.RLock()
PUBLIC_UPLOAD_STATS = {
    "received": 0,
    "rate_limited_ips": set(),
}
UPLOAD_REQUEST_LOCK = threading.RLock()
PENDING_UPLOAD_REQUESTS: dict[str, dict] = {}
PUBLIC_UPLOAD_GRANTS: dict[str, dict] = {}
PUBLIC_UPLOAD_REQUEST_TTL_SECONDS = 2 * 60


def reload_protected_vault_state() -> bool:
    """Reload encrypted sensitive settings after an interactive unlock."""
    global _CONFIG, _DATA_VAULT_BOOT_ERROR
    global TOTP_SECRET, TRUSTED_DEVICES
    global COMMUNITY_PASSWORD, ADMIN_PASSWORD
    global COMMUNITY_PASSWORD_CREDENTIAL, ADMIN_PASSWORD_CREDENTIAL, WEB_PASSWORD_CREDENTIAL
    global SAVED_LOCAL_PASSWORD, LOCAL_PASSWORD, LOCAL_PASSWORD_SAVED_AT
    global FOLDER_SHARE_HISTORY, FOLDER_PAIR_HISTORY, HIDDEN_PATHS

    from src.core.data_vault import get_data_vault
    vault = get_data_vault(_CONFIG_DIR)
    if not vault.configured or not vault.unlocked:
        return False
    merged = _merge_protected_config(_load_config())
    if PROTECTED_CONFIG_PATH.exists() and _DATA_VAULT_BOOT_ERROR:
        return False
    _CONFIG = merged
    TOTP_SECRET = str(merged.get("totp_secret") or TOTP_SECRET or pyotp.random_base32())
    TRUSTED_DEVICES = {str(k): v for k, v in dict(merged.get("trusted_devices") or {}).items()}
    COMMUNITY_PASSWORD = str(merged.get("community_password") or "")
    ADMIN_PASSWORD = str(merged.get("admin_password") or "")
    COMMUNITY_PASSWORD_CREDENTIAL = str(merged.get("community_password_credential") or "")
    ADMIN_PASSWORD_CREDENTIAL = str(merged.get("admin_password_credential") or "")
    WEB_PASSWORD_CREDENTIAL = str(merged.get("web_password_credential") or "")
    SAVED_LOCAL_PASSWORD = str(merged.get("local_password") or "")
    LOCAL_PASSWORD = SAVED_LOCAL_PASSWORD
    LOCAL_PASSWORD_SAVED_AT = float(merged.get("local_password_saved_at") or 0.0)
    FOLDER_SHARE_HISTORY = [
        {
            "path": str(item.get("path") or ""),
            "share_count": max(1, int(item.get("share_count") or 1)),
            "last_shared_at": float(item.get("last_shared_at") or 0.0),
        }
        for item in list(merged.get("folder_share_history") or [])
        if isinstance(item, dict) and item.get("path")
    ]
    FOLDER_PAIR_HISTORY = [
        {
            "paths": [str(path) for path in item.get("paths", [])[:2]],
            "share_count": max(1, int(item.get("share_count") or 1)),
            "last_shared_at": float(item.get("last_shared_at") or 0.0),
        }
        for item in list(merged.get("folder_pair_history") or [])
        if isinstance(item, dict) and len(item.get("paths") or []) == 2
    ]
    HIDDEN_PATHS = {
        slot: sorted({
            "/" + str(path).strip().replace("\\", "/").strip("/")
            for path in list(dict(merged.get("hidden_paths") or {}).get(slot) or [])
            if str(path).strip().strip("/")
        })
        for slot in ("slot-1", "slot-2")
    }
    _DATA_VAULT_BOOT_ERROR = ""
    return True


def try_auto_unlock_data_vault() -> bool:
    """Retry only transparent Data Vault unlock paths after desktop startup.

    macOS Keychain access can be unavailable during early module import, before
    the Cocoa application loop exists.  This helper is intentionally safe to
    call later from the desktop/API layers.  It never guesses a password and
    never falls back to plaintext storage: OS mode and explicitly remembered
    password mode are the only automatic unlock paths.
    """
    global _DATA_VAULT_BOOT_ERROR
    try:
        from src.core.data_vault import get_data_vault
        vault = get_data_vault(_CONFIG_DIR)
        if not vault.configured:
            _DATA_VAULT_BOOT_ERROR = ""
            return True
        if not vault.unlocked:
            status = vault.status()
            if status.mode == "os":
                vault.unlock_os()
            elif status.mode == "password" and status.remember_on_windows:
                if not vault.try_unlock_remembered():
                    return False
            else:
                # A password vault without Remember is expected to remain
                # locked until the user explicitly unlocks it in Settings.
                return False
        if not vault.unlocked:
            return False
        if not reload_protected_vault_state():
            return False
        _DATA_VAULT_BOOT_ERROR = ""
        return True
    except Exception as exc:
        _DATA_VAULT_BOOT_ERROR = f"{type(exc).__name__}: {exc}"
        return False


def data_vault_boot_error() -> str:
    return str(_DATA_VAULT_BOOT_ERROR or "")


_save_config()


def save_local_password(password: str, *, saved_at: float | None = None) -> None:
    """Persist the LAN password and restart its change-reminder clock."""
    global LOCAL_PASSWORD, SAVED_LOCAL_PASSWORD, LOCAL_PASSWORD_SAVED_AT
    SAVED_LOCAL_PASSWORD = str(password).strip()
    LOCAL_PASSWORD = SAVED_LOCAL_PASSWORD
    LOCAL_PASSWORD_SAVED_AT = float(saved_at if saved_at is not None else time.time())
    _save_config()


def password_reminder_due(*, now: float | None = None) -> bool:
    if not SAVED_LOCAL_PASSWORD or LOCAL_PASSWORD_SAVED_AT <= 0:
        return False
    current = float(now if now is not None else time.time())
    return current >= LOCAL_PASSWORD_SAVED_AT + PASSWORD_REMINDER_DAYS * 86400


def postpone_password_reminder(*, now: float | None = None) -> None:
    global LOCAL_PASSWORD_SAVED_AT
    LOCAL_PASSWORD_SAVED_AT = float(now if now is not None else time.time())
    _save_config()


def save_password_reminder_days(days: int) -> None:
    """Persist the user-selected password reminder interval."""
    global PASSWORD_REMINDER_DAYS
    value = int(days)
    if not 1 <= value <= 3650:
        raise ValueError("password reminder must be between 1 and 3650 days")
    PASSWORD_REMINDER_DAYS = value
    _save_config()


def save_appearance(*, theme: str | None = None, text_size: str | None = None) -> None:
    """Persist validated GUI appearance choices in the shared config."""
    global THEME, TEXT_SIZE
    if theme is not None:
        value = str(theme).lower()
        if value not in ("system", "dark", "light"):
            raise ValueError("theme must be system, dark or light")
        THEME = value
    if text_size is not None:
        value = str(text_size).lower()
        if value not in ("small", "normal", "large"):
            raise ValueError("text size must be small, normal or large")
        TEXT_SIZE = value
    _save_config()


def save_language(language: str) -> None:
    global LANGUAGE
    value = str(language or "").lower()
    if value != "system":
        from src.i18n import LANGUAGES
        if value not in LANGUAGES:
            raise ValueError("unsupported language")
    LANGUAGE = value
    _save_config()


def record_folder_share(path: str, *, shared_at: float | None = None) -> None:
    """Record a successful share, preserving frequency and recency."""
    clean = str(Path(path).resolve())
    timestamp = float(shared_at if shared_at is not None else time.time())
    match = next((item for item in FOLDER_SHARE_HISTORY if item["path"] == clean), None)
    if match is None:
        FOLDER_SHARE_HISTORY.append({"path": clean, "share_count": 1, "last_shared_at": timestamp})
    else:
        match["share_count"] += 1
        match["last_shared_at"] = timestamp
    FOLDER_SHARE_HISTORY.sort(key=lambda item: item["last_shared_at"], reverse=True)
    del FOLDER_SHARE_HISTORY[100:]
    _save_config()


def recommended_folders(limit: int = 3) -> list[dict]:
    """Return existing folders ranked by share frequency, then recency."""
    existing = [item.copy() for item in FOLDER_SHARE_HISTORY if Path(item["path"]).is_dir()]
    existing.sort(key=lambda item: (item["share_count"], item["last_shared_at"]), reverse=True)
    return existing[:max(0, int(limit))]


def clear_folder_share_history() -> None:
    FOLDER_SHARE_HISTORY.clear()
    FOLDER_PAIR_HISTORY.clear()
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

# General traffic throttle for requests arriving through a public tunnel
# (SSH or Cloudflare) -- distinct from AUTH_RATE_LIMITS, which only tracks
# failed password/TOTP attempts. This one caps total request volume per IP
# regardless of whether the request authenticates successfully, so a public
# tunnel can't be hammered into a de-facto DoS against the local machine.
GENERAL_RATE_LIMIT_MAX = 120
GENERAL_RATE_LIMIT_WINDOW_SECONDS = 60
GENERAL_RATE_LIMITS: dict[str, list[float]] = {}
GENERAL_RATE_LOCK = threading.RLock()
MIGRATION_CHALLENGE_TTL_SECONDS = 60
MIGRATION_CHALLENGES: dict[str, dict] = {}


def general_request_allowed(key: str) -> bool:
    """Record this request and return False once the rolling-window cap is hit."""
    now = time.time()
    cutoff = now - GENERAL_RATE_LIMIT_WINDOW_SECONDS
    with GENERAL_RATE_LOCK:
        attempts = [ts for ts in GENERAL_RATE_LIMITS.get(key, []) if ts >= cutoff]
        attempts.append(now)
        GENERAL_RATE_LIMITS[key] = attempts
        return len(attempts) <= GENERAL_RATE_LIMIT_MAX


def verify_totp(code: str) -> bool:
    """Return True when *code* is a valid TOTP for this server."""
    clean = "".join(ch for ch in str(code).strip() if ch.isdigit())
    if len(clean) != 6:
        return False
    return bool(pyotp.TOTP(TOTP_SECRET).verify(clean, valid_window=1))


def _credential_hash(credential: str) -> str:
    return hashlib.sha256(str(credential).encode("utf-8")).hexdigest()


def register_device(device_id: str, code: str) -> str | None:
    """Trust a device and return its new opaque credential exactly once."""
    clean_id = str(device_id).strip()
    if not clean_id or not (consume_write_otp(code) or verify_totp(code)):
        return None
    credential = secrets.token_urlsafe(32)
    with WRITE_AUTH_LOCK:
        TRUSTED_DEVICES[clean_id] = {
            "paired_at": time.time(),
            "credential_hash": _credential_hash(credential),
        }
        _save_config()
    return credential


def is_trusted_device(device_id: str) -> bool:
    """Return True when a device ID has already been registered as trusted."""
    clean_id = str(device_id or "").strip()
    return bool(clean_id and clean_id in TRUSTED_DEVICES)


def verify_device_credential(device_id: str, credential: str) -> bool:
    clean_id = str(device_id or "").strip()
    record = TRUSTED_DEVICES.get(clean_id)
    if not clean_id or not credential or not isinstance(record, dict):
        return False
    expected = str(record.get("credential_hash") or "")
    return bool(expected and hmac.compare_digest(expected, _credential_hash(credential)))


def create_migration_challenge(previous_id: str, current_id: str) -> str:
    now = time.time()
    challenge = secrets.token_urlsafe(24)
    with WRITE_AUTH_LOCK:
        MIGRATION_CHALLENGES.clear()
        MIGRATION_CHALLENGES[_credential_hash(challenge)] = {
            "previous_id": str(previous_id),
            "current_id": str(current_id),
            "expires_at": now + MIGRATION_CHALLENGE_TTL_SECONDS,
        }
    return challenge


def consume_migration_challenge(challenge: str, previous_id: str, current_id: str) -> bool:
    key = _credential_hash(challenge)
    with WRITE_AUTH_LOCK:
        record = MIGRATION_CHALLENGES.pop(key, None)
    return bool(
        record
        and record["expires_at"] >= time.time()
        and hmac.compare_digest(record["previous_id"], str(previous_id))
        and hmac.compare_digest(record["current_id"], str(current_id))
    )


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
    global COMMUNITY_PASSWORD_CREDENTIAL, ADMIN_PASSWORD_CREDENTIAL
    if COMMUNITY_PASSWORD:
        COMMUNITY_PASSWORD_CREDENTIAL = hash_password(COMMUNITY_PASSWORD)
    if ADMIN_PASSWORD:
        ADMIN_PASSWORD_CREDENTIAL = hash_password(ADMIN_PASSWORD)
    _save_config()


def verify_admin_password(password: str) -> bool:
    return bool(
        (ADMIN_PASSWORD_CREDENTIAL and verify_password(password, ADMIN_PASSWORD_CREDENTIAL))
        or (ADMIN_PASSWORD and hmac.compare_digest(str(password), ADMIN_PASSWORD))
    )


def has_admin_password() -> bool:
    return bool(ADMIN_PASSWORD_CREDENTIAL or ADMIN_PASSWORD or TUNNEL_PASSWORD)


def verify_community_password(password: str) -> bool:
    return bool(
        (COMMUNITY_PASSWORD_CREDENTIAL and verify_password(password, COMMUNITY_PASSWORD_CREDENTIAL))
        or (COMMUNITY_PASSWORD and hmac.compare_digest(str(password), COMMUNITY_PASSWORD))
    )


def has_community_password() -> bool:
    return bool(COMMUNITY_PASSWORD_CREDENTIAL or COMMUNITY_PASSWORD)


def set_web_password(password: str, *, enabled: bool = True) -> None:
    global WEB_PASSWORD_CREDENTIAL, WEB_ACCESS_ENABLED, WEB_CREDENTIAL_GENERATION
    WEB_PASSWORD_CREDENTIAL = hash_password(password)
    WEB_ACCESS_ENABLED = bool(enabled)
    WEB_CREDENTIAL_GENERATION += 1
    _save_config()


def verify_web_password(password: str) -> bool:
    return bool(
        WEB_ACCESS_ENABLED
        and WEB_PASSWORD_CREDENTIAL
        and verify_password(password, WEB_PASSWORD_CREDENTIAL)
    )


def disable_web_access() -> None:
    global WEB_ACCESS_ENABLED, WEB_CREDENTIAL_GENERATION
    WEB_ACCESS_ENABLED = False
    WEB_CREDENTIAL_GENERATION += 1
    _save_config()


def record_folder_pair(paths, *, shared_at: float | None = None) -> None:
    clean = [str(Path(path).resolve()) for path in list(paths)[:2]]
    if len(clean) != 2:
        return
    timestamp = float(shared_at if shared_at is not None else time.time())
    match = next((item for item in FOLDER_PAIR_HISTORY if item["paths"] == clean), None)
    if match is None:
        FOLDER_PAIR_HISTORY.append({"paths": clean, "share_count": 1, "last_shared_at": timestamp})
    else:
        match["share_count"] += 1
        match["last_shared_at"] = timestamp
    FOLDER_PAIR_HISTORY.sort(key=lambda item: item["last_shared_at"], reverse=True)
    del FOLDER_PAIR_HISTORY[50:]
    _save_config()


def set_shared_roots(paths, *, persist: bool = True) -> tuple[SharedRoot, ...]:
    """Set at most two local roots while keeping ROOT_DIR as the legacy slot 1."""
    global ROOT_DIR, SHARED_ROOTS
    roots = normalize_shared_roots(list(paths)[:2])
    if not roots:
        raise ValueError("at least one shared root is required")
    SHARED_ROOTS = roots
    ROOT_DIR = roots[0].path
    if persist:
        _save_config()
    return SHARED_ROOTS


def root_for_slot(slot: str) -> Path | None:
    return next((root.path for root in SHARED_ROOTS if root.slot == slot), None)


def set_hidden_path(slot: str, relative_path: str, hidden: bool) -> bool:
    """Persist a global folder visibility rule for one shared-root slot."""
    if root_for_slot(slot) is None:
        raise ValueError("unknown shared-root slot")
    clean = "/" + str(relative_path or "").replace("\\", "/").strip("/")
    if clean == "/" or ".." in clean.split("/"):
        raise ValueError("invalid hidden path")
    values = HIDDEN_PATHS.setdefault(slot, [])
    changed = False
    if hidden and clean not in values:
        values.append(clean)
        values.sort()
        changed = True
    elif not hidden and clean in values:
        values.remove(clean)
        changed = True
    if changed:
        _save_config()
    return changed


def save_cluster_role(role: str) -> None:
    global CLUSTER_ROLE
    value = str(role).strip().lower()
    if value not in ("standalone", "auto", "master", "slave"):
        raise ValueError("invalid cluster role")
    CLUSTER_ROLE = value
    _save_config()


def effective_cluster_role() -> str:
    """Return the cryptographic role currently active for cluster I/O."""
    manager = globals().get("_cluster_runtime")
    effective = str(getattr(manager, "effective_role", "") or "")
    if effective in ("master", "slave"):
        return effective
    return CLUSTER_ROLE if CLUSTER_ROLE in ("master", "slave") else "standalone"


def save_keep_awake_enabled(enabled: bool) -> None:
    """Persist the user's Keep Alive preference; the runtime lock is separate."""
    global KEEP_AWAKE_ENABLED
    KEEP_AWAKE_ENABLED = bool(enabled)
    _save_config()


def save_security_monitor_config(values: dict) -> dict:
    """Validate, persist and return the complete security-monitor configuration."""
    global SECURITY_MONITOR_CONFIG
    if not isinstance(values, dict):
        raise ValueError("security monitor configuration must be an object")
    merged = dict(SECURITY_MONITOR_CONFIG)
    merged.update(values)
    SECURITY_MONITOR_CONFIG = _normalized_security_monitor_config(merged)
    _save_config()
    return dict(SECURITY_MONITOR_CONFIG)


def save_show_advanced_settings(enabled: bool) -> None:
    """Persist whether advanced feature sections are visible in Settings."""
    global SHOW_ADVANCED_SETTINGS
    SHOW_ADVANCED_SETTINGS = bool(enabled)
    _save_config()


def save_data_vault_prompt_state(value: str) -> str:
    global DATA_VAULT_PROMPT_STATE
    state = str(value or "").strip().lower()
    if state not in _DATA_VAULT_PROMPT_STATES:
        raise ValueError("invalid data vault prompt state")
    DATA_VAULT_PROMPT_STATE = state
    _save_config()
    return DATA_VAULT_PROMPT_STATE


def data_vault_prompt_snapshot() -> dict:
    return {
        "state": DATA_VAULT_PROMPT_STATE,
        "context": DATA_VAULT_PROMPT_CONTEXT,
    }


def save_ffmpeg_path(path: str) -> None:
    """Persist an optional user-selected FFmpeg executable path."""
    global FFMPEG_PATH
    FFMPEG_PATH = str(path or "").strip()
    _save_config()


def save_gpu_encoder_preference(preference: str, capabilities=None) -> None:
    """Persist only GPU choices bounded by a successfully verified backend."""
    global GPU_ENCODER_PREFERENCE
    value = str(preference or "").strip().lower()
    allowed = {"auto", "cpu", "gpu", "nvenc", "qsv", "amf", "videotoolbox"}
    if value not in allowed:
        raise ValueError("invalid GPU encoder preference")
    if capabilities is None:
        import src.deps as deps
        capabilities = deps.FFMPEG_CAPABILITIES
    verified = {
        name for name, backend in capabilities.gpu_encoders.items()
        if backend.verified
    }
    if value == "gpu" and not verified:
        raise ValueError("no verified GPU encoder")
    if value in {"nvenc", "qsv", "amf", "videotoolbox"} and value not in verified:
        raise ValueError("GPU encoder backend is not verified")
    GPU_ENCODER_PREFERENCE = value
    _save_config()


def save_log_buffer_lines(value: object) -> int:
    """Clamp and persist the shared diagnostic-view and ingress-queue budget."""
    global LOG_BUFFER_LINES
    from src.core.bounded_logs import clamp_log_buffer_lines, log_queue_capacity

    LOG_BUFFER_LINES = clamp_log_buffer_lines(value)
    if "_log_queue" in globals():
        _log_queue.resize(log_queue_capacity(LOG_BUFFER_LINES))
    if "_write_activity_queue" in globals():
        _write_activity_queue.resize(log_queue_capacity(LOG_BUFFER_LINES))
    try:
        from src.runtime.activity_runtime import activity_runtime
        activity_runtime.resize(LOG_BUFFER_LINES)
    except Exception:
        pass
    _save_config()
    return LOG_BUFFER_LINES


def save_performance_preset(preset: str) -> None:
    """Persist and immediately apply a supported HLS performance preset."""
    global PERFORMANCE_PRESET, INDEX_WORKERS, ANALYSIS_WORKERS
    value = str(preset or "").strip().lower()
    if value not in ("economy", "balanced_light", "balanced", "performance"):
        raise ValueError("invalid performance preset")
    PERFORMANCE_PRESET = value
    from src.core.performance_resources import effective_worker_budget, logical_cpu_count
    worker_budget = effective_worker_budget(value, logical_cpu_count())
    INDEX_WORKERS = worker_budget.index_workers
    ANALYSIS_WORKERS = worker_budget.analysis_workers
    _save_config()
    from src.core import adaptive_streaming
    adaptive_streaming.configure_performance_preset(value)
    try:
        from src.core.file_index import _file_index, configure_watcher_performance
        _file_index.configure_worker_budget(worker_budget)
        configure_watcher_performance(value)
    except ImportError:
        pass


def save_worker_budget(index_workers: object, analysis_workers: object, *, changed: str) -> object:
    """Clamp, persist and publish a worker budget derived from actual CPU count."""
    global INDEX_WORKERS, ANALYSIS_WORKERS
    from src.core.performance_resources import clamp_worker_budget, logical_cpu_count

    budget = clamp_worker_budget(
        index_workers, analysis_workers, logical_cpu_count(), changed=changed,
    )
    INDEX_WORKERS = budget.index_workers
    ANALYSIS_WORKERS = budget.analysis_workers
    _save_config()
    try:
        from src.core.file_index import _file_index
        _file_index.configure_worker_budget(budget)
    except ImportError:
        pass
    return budget


def migrate_trusted_device(previous_device_id: str, device_id: str) -> bool:
    """Move a local trusted-device registration to its scoped replacement."""
    previous = str(previous_device_id or "").strip()
    current = str(device_id or "").strip()
    if not previous or not current or previous == current or previous not in TRUSTED_DEVICES:
        return False
    registered_at = TRUSTED_DEVICES.pop(previous)
    TRUSTED_DEVICES.setdefault(current, registered_at)
    _save_config()
    return True


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


def consume_write_otp(otp: str) -> bool:
    """Consume the displayed local-pairing code once, if it is still valid."""
    global WRITE_OTP, WRITE_OTP_EXPIRES_AT
    now = time.time()
    clean = str(otp).strip()
    with WRITE_AUTH_LOCK:
        if (
            not WRITE_OTP
            or now > WRITE_OTP_EXPIRES_AT
            or not hmac.compare_digest(clean, WRITE_OTP)
        ):
            return False
        WRITE_OTP = ""
        WRITE_OTP_EXPIRES_AT = 0.0
        return True


def expire_write_otp() -> None:
    """Remove the displayed pairing code without changing issued credentials."""
    global WRITE_OTP, WRITE_OTP_EXPIRES_AT
    with WRITE_AUTH_LOCK:
        WRITE_OTP = ""
        WRITE_OTP_EXPIRES_AT = 0.0


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


def clear_auth_failures_by_prefix(prefix: str) -> int:
    """Clear matching auth buckets after a credential rotation."""
    clean = str(prefix or "")
    if not clean:
        return 0
    with AUTH_RATE_LOCK:
        keys = [key for key in AUTH_RATE_LIMITS if key.startswith(clean)]
        for key in keys:
            AUTH_RATE_LIMITS.pop(key, None)
    return len(keys)

# Log pipeline
# _log_callback is set to a no-op lambda while the server is running so that
# _emit() stops calling print(); the GUI drains _log_queue via a Tkinter timer.

from src.core.bounded_logs import BoundedEventQueue, log_queue_capacity

_log_queue = BoundedEventQueue(log_queue_capacity(LOG_BUFFER_LINES))
_log_callback              = None        # set by App._start_server
_write_activity_queue = BoundedEventQueue(log_queue_capacity(LOG_BUFFER_LINES))


def _emit(msg: str, kind: str = "info"):
    """Put a log entry on the legacy queue and tee a non-destructive UI copy."""
    _log_queue.put((msg, kind))
    try:
        from src.runtime.activity_runtime import activity_runtime
        activity_runtime.publish_log(msg, kind)
    except Exception:
        # Observability/fan-out must never change the legacy producer path.
        pass
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
    event = {
        "action": action,
        "path": path,
        "size": size,
        "client": client,
        "request_id": request_id,
        "time": time.time(),
    }
    _write_activity_queue.put(event)
    try:
        from src.runtime.activity_runtime import activity_runtime
        activity_runtime.publish_write(event)
    except Exception:
        pass


# Runtime singletons (set/cleared by App)
# These are mutable references; always access via  state._ws_manager  etc.

_ws_manager  = None   # core.websocket_manager.WebSocketManager | None
_cluster_controller = None  # core.cluster.control.ClusterControlService | None
_cluster_relay = None  # core.cluster.relay.MasterRelay | None
_cluster_runtime = None  # core.cluster.runtime.ClusterRuntimeManager | None
