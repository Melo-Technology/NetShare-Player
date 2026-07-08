"""
Firebase Remote Config synchronization for feature flags.

Startup prefers a fresh local cache, falls back to the network when the cache is
stale or missing, and finally uses stale cache data when Firebase is unavailable.
Background polling uses ETags so unchanged configs avoid unnecessary writes.
"""

import gzip
import json
import os
import sys
import threading
import time
from pathlib import Path

_SERVICE_ACCOUNT = Path(__file__).parent.parent / "service_account.json"
_initialized = False
_lock = threading.Lock()

if getattr(sys, "frozen", False):
    _CACHE_DIR: Path = Path(sys.executable).parent
else:
    _CACHE_DIR: Path = Path(__file__).parent.parent.parent

_CACHE_FILE: Path  = _CACHE_DIR / "remote_config_cache.json"
_CACHE_MAX_AGE: int = 24 * 60 * 60   # treat as stale after 24 h
_POLL_INTERVAL: int =  5 * 60        # background change-detection every 5 min

_poll_stop   = threading.Event()
_poll_thread: threading.Thread | None = None


# Cache helpers

def _save_cache(flags: dict[str, bool], etag: str = "") -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(
            json.dumps(
                {"flags": flags, "fetched_at": time.time(), "etag": etag},
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Remote config: cache saved -> {_CACHE_FILE}")
    except OSError as e:
        print(f"Remote config: cache save failed - {e}")


def _load_cache() -> tuple[dict[str, bool] | None, bool, str]:
    """Returns (flags, is_fresh, etag)."""
    try:
        if not _CACHE_FILE.exists():
            return None, False, ""
        data       = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        flags      = data.get("flags")
        fetched_at = float(data.get("fetched_at", 0))
        etag       = str(data.get("etag", ""))
        if not isinstance(flags, dict):
            return None, False, ""
        age      = time.time() - fetched_at
        is_fresh = age < _CACHE_MAX_AGE
        if not is_fresh:
            print(f"Remote config: cache is stale ({int(age // 3600)}h old)")
        return flags, is_fresh, etag
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"Remote config: cache load failed - {e}")
        return None, False, ""


# Firebase init

def init() -> None:
    global _initialized
    try:
        import firebase_admin
        from firebase_admin import credentials
    except ImportError:
        return
    if not _SERVICE_ACCOUNT.exists():
        print(f"Firebase: service_account.json not found at {_SERVICE_ACCOUNT}")
        return
    with _lock:
        if _initialized:
            return
        try:
            cred = credentials.Certificate(str(_SERVICE_ACCOUNT))
            firebase_admin.initialize_app(cred)
            _initialized = True
            print(f"Firebase initialized - cache: {_CACHE_FILE}")
        except Exception as e:
            print(f"Firebase init failed: {e}")


# Network fetch (ETag-aware)

def _fetch_from_network(etag: str = "") -> tuple[dict[str, bool] | None, str]:
    """
    Returns (flags, new_etag).
    flags is None when:
      - nothing changed (304 - etag unchanged, no write needed)
      - a network/auth error occurred
    """
    try:
        import urllib.request
        import urllib.error
        import google.auth.transport.requests
        import google.oauth2.service_account

        if not _SERVICE_ACCOUNT.exists():
            print(f"Remote config: service_account.json not found ({_SERVICE_ACCOUNT})")
            return None, etag

        creds = google.oauth2.service_account.Credentials.from_service_account_file(
            str(_SERVICE_ACCOUNT),
            scopes=["https://www.googleapis.com/auth/firebase.remoteconfig"],
        )
        creds.refresh(google.auth.transport.requests.Request())

        sa_data    = json.loads(_SERVICE_ACCOUNT.read_text(encoding="utf-8"))
        project_id = sa_data["project_id"]
        url        = (
            f"https://firebaseremoteconfig.googleapis.com"
            f"/v1/projects/{project_id}/remoteConfig"
        )

        headers = {"Authorization": f"Bearer {creds.token}"}
        if etag:
            headers["If-None-Match"] = etag   # cheap change-detection

        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                new_etag = resp.headers.get("ETag", "")
                raw = resp.read()
                if raw[:2] == b"\x1f\x8b":
                    raw = gzip.decompress(raw)
                data = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 304:
                print("Remote config: no changes (304 Not Modified)")
                return None, etag   # unchanged - caller keeps existing cache
            raise

        params = data.get("parameters", {})

        def _get_bool(key: str, default: bool = True) -> bool:
            param = params.get(key, {})
            value = (
                param.get("defaultValue", {}).get("value", "") or str(default)
            ).lower()
            return value in ("true", "1", "yes")

        flags = {
            "upload":        _get_bool("feature_send_files",    default=True),
            "document_edit": _get_bool("feature_edit_document", default=True),
        }
        print(f"Remote config: fetched from network - {flags}  (ETag: {new_etag[:16]}...)")
        return flags, new_etag

    except Exception as e:
        print(f"Remote config: network fetch failed - {e}")
        return None, etag


# Background polling

def start_polling(on_change) -> None:
    """
    Spawn a daemon thread that checks Firebase every _POLL_INTERVAL seconds.
    on_change(flags) is called on the polling thread whenever flags differ
    from the cached values - wire it to Tkinter's `after()` for GUI safety.
    """
    global _poll_thread
    _poll_stop.clear()
    _poll_thread = threading.Thread(
        target=_poll_loop, args=(on_change,), daemon=True, name="RemoteConfigPoller"
    )
    _poll_thread.start()
    print(f"Remote config: polling started (interval={_POLL_INTERVAL // 60} min)")


def stop_polling() -> None:
    """Signal the polling thread to stop (called on app close)."""
    _poll_stop.set()


def _poll_loop(on_change) -> None:
    while not _poll_stop.wait(_POLL_INTERVAL):
        _check_for_changes(on_change)


def _check_for_changes(on_change) -> None:
    """One poll tick - uses ETag so a 304 costs almost nothing."""
    cached_flags, _, etag = _load_cache()
    live_flags, new_etag  = _fetch_from_network(etag)

    if live_flags is None:
        return   # 304 (no change) or network error

    _save_cache(live_flags, new_etag)

    if live_flags != cached_flags:
        print(f"Remote config: flags changed -> {live_flags}")
        try:
            on_change(live_flags)
        except Exception as e:
            print(f"Remote config: on_change callback error - {e}")


# Public API

def fetch_feature_flags() -> dict[str, bool]:
    """
    Startup fetch.
      1. Fresh cache  -> return immediately (no network)
      2. Stale/absent -> network fetch + save cache
      3. Network fail -> stale cache or {}
    """
    cached_flags, is_fresh, etag = _load_cache()

    if cached_flags is not None and is_fresh:
        print("Remote config: using fresh cache")
        return cached_flags

    init()
    live_flags, new_etag = _fetch_from_network(etag)
    if live_flags is not None:
        _save_cache(live_flags, new_etag)
        return live_flags

    if cached_flags is not None:
        print("Remote config: network unavailable - using stale cache")
        return cached_flags

    print("Remote config: no cache and no network - showing everything")
    return {}