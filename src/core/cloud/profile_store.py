"""Encrypted persistence for reconnectable cloud connector profiles.

This store is intentionally separate from OAuth/session tokens. Disconnecting an
account removes its live token entry but may keep the connector profile (Google
OAuth client id/secret, Dropbox app key, or Mega email) so the host can reconnect
without retyping setup values.

Security model:
* plaintext connector credentials are never written to disk;
* encryption uses Fernet from ``cryptography``;
* on Windows the Fernet master key is wrapped with per-user DPAPI before it is
  written to disk, so copying the NetShare config directory is insufficient to
  decrypt the profiles;
* on non-Windows systems the fallback key file is owner-only (0600).  The API
  reports this weaker backend so the UI can remain honest about protection.

No at-rest mechanism can protect a secret from an attacker already executing
code as the same user/process while NetShare is running, because NetShare itself
must be able to decrypt the credential to reconnect.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
import time
from typing import Any

import src.state as state
from src.deps import HAS_CRYPTOGRAPHY
from src.core.data_vault import secure_unlink

def _store_path() -> Path:
    return Path(state._CONFIG_DIR) / "cloud_profiles.dat"

def _key_path() -> Path:
    return Path(state._CONFIG_DIR) / "cloud_profiles.key"


def _restrict_permissions(path: Path) -> None:
    try:
        if os.name != "nt":
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    _restrict_permissions(tmp)
    os.replace(tmp, path)
    _restrict_permissions(path)


def _dpapi_protect(payload: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("dpapi_unavailable")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    source = ctypes.create_string_buffer(payload)
    source_blob = DATA_BLOB(len(payload), ctypes.cast(source, ctypes.POINTER(ctypes.c_byte)))
    output_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    ok = crypt32.CryptProtectData(
        ctypes.byref(source_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    if not ok:
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


def _dpapi_unprotect(payload: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("dpapi_unavailable")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    source = ctypes.create_string_buffer(payload)
    source_blob = DATA_BLOB(len(payload), ctypes.cast(source, ctypes.POINTER(ctypes.c_byte)))
    output_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(source_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    if not ok:
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


class CloudProfileStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._fernet = None
        self._backend = "unavailable"
        self._config_dir = Path(state._CONFIG_DIR)
        if HAS_CRYPTOGRAPHY:
            self._fernet = self._load_or_create_fernet()

    def _ensure_context(self) -> None:
        current = Path(state._CONFIG_DIR)
        if current == self._config_dir:
            return
        self._config_dir = current
        self._backend = "unavailable"
        self._fernet = self._load_or_create_fernet() if HAS_CRYPTOGRAPHY else None

    def _load_or_create_fernet(self):
        from cryptography.fernet import Fernet

        state._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            if _key_path().exists():
                key = _dpapi_unprotect(_key_path().read_bytes())
            else:
                key = Fernet.generate_key()
                _atomic_write(_key_path(), _dpapi_protect(key))
            self._backend = "windows_dpapi"
            return Fernet(key)

        if _key_path().exists():
            key = _key_path().read_bytes()
        else:
            key = Fernet.generate_key()
            _atomic_write(_key_path(), key)
        _restrict_permissions(_key_path())
        self._backend = "fernet_owner_only"
        return Fernet(key)

    @property
    def available(self) -> bool:
        self._ensure_context()
        return self._fernet is not None

    @property
    def backend(self) -> str:
        self._ensure_context()
        return self._backend

    @property
    def strong_os_protection(self) -> bool:
        return self._backend == "windows_dpapi"

    def _read_all(self) -> dict:
        self._ensure_context()
        if not _store_path().exists():
            return {"version": 1, "profiles": {}}
        if self._fernet is None:
            return {"version": 1, "profiles": {}}
        try:
            raw = self._fernet.decrypt(_store_path().read_bytes())
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("profiles", {}), dict):
                raise ValueError("invalid profile store")
            return {"version": 1, "profiles": dict(data.get("profiles", {}))}
        except Exception:
            # Never fall back to parsing ciphertext/plaintext ambiguously.
            return {"version": 1, "profiles": {}}

    def _write_all(self, data: dict) -> None:
        self._ensure_context()
        if self._fernet is None:
            raise RuntimeError("secure_cloud_profile_storage_unavailable")
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        _atomic_write(_store_path(), self._fernet.encrypt(payload))

    @staticmethod
    def profile_id(provider_id: str, account_id: str) -> str:
        material = f"{provider_id.strip().lower()}\0{account_id.strip()}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:24]

    def save(
        self,
        provider_id: str,
        account_id: str,
        label: str,
        config: dict[str, Any],
    ) -> dict:
        if not self.available:
            raise RuntimeError("secure_cloud_profile_storage_unavailable")
        pid = self.profile_id(provider_id, account_id)
        clean_provider = str(provider_id or "").strip().lower()
        clean_account = str(account_id or "").strip()
        clean_config = {str(k): str(v) for k, v in dict(config or {}).items() if str(v or "")}
        record = {
            "profile_id": pid,
            "provider_id": clean_provider,
            "account_id": clean_account,
            "label": str(label or clean_account),
            "config": clean_config,
            "updated_at": time.time(),
        }
        with self._lock:
            data = self._read_all()
            data.setdefault("profiles", {})[pid] = record
            self._write_all(data)
        return self.metadata(record)

    def get(self, profile_id: str) -> dict | None:
        with self._lock:
            value = self._read_all().get("profiles", {}).get(str(profile_id))
        return dict(value) if isinstance(value, dict) else None

    def delete(self, profile_id: str) -> bool:
        with self._lock:
            data = self._read_all()
            removed = data.setdefault("profiles", {}).pop(str(profile_id), None) is not None
            if removed:
                self._write_all(data)
            return removed

    def clear(self) -> dict[str, int]:
        with self._lock:
            count = len(self._read_all().get("profiles", {}))
            for path in (_store_path(), _key_path()):
                try:
                    secure_unlink(path)
                except OSError:
                    pass
            # Re-create the in-memory cipher lazily now so subsequent saves in
            # the same process use a fresh key instead of retaining deleted key material.
            self._fernet = self._load_or_create_fernet() if HAS_CRYPTOGRAPHY else None
        return {"profiles": int(count)}

    @staticmethod
    def metadata(record: dict) -> dict:
        config = dict(record.get("config") or {})
        return {
            "profile_id": str(record.get("profile_id") or ""),
            "provider_id": str(record.get("provider_id") or ""),
            "account_id": str(record.get("account_id") or ""),
            "label": str(record.get("label") or record.get("account_id") or ""),
            "has_client_id": bool(config.get("client_id")),
            "has_client_secret": bool(config.get("client_secret")),
            "has_app_key": bool(config.get("app_key")),
            "email": str(config.get("email") or ""),
            "requires_password": str(record.get("provider_id") or "") == "mega",
            "updated_at": float(record.get("updated_at") or 0.0),
        }

    def list_metadata(self) -> list[dict]:
        with self._lock:
            profiles = list(self._read_all().get("profiles", {}).values())
        return [self.metadata(item) for item in profiles if isinstance(item, dict)]

    def storage_info(self) -> dict:
        return {
            "available": bool(self.available),
            "backend": str(self.backend),
            "os_protected": bool(self.strong_os_protection),
        }


_store: CloudProfileStore | None = None
_store_lock = threading.Lock()


def get_profile_store() -> CloudProfileStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = CloudProfileStore()
        return _store
