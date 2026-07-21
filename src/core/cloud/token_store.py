"""
Local persistence for cloud provider tokens/credentials.

Security tradeoff (flagged rather than hidden, per the "encrypted if
possible, restricted permissions at minimum" requirement):

- If the optional `cryptography` package is installed, tokens are encrypted
  at rest with Fernet (AES-128-CBC + HMAC), using a key generated on first
  run and stored in a sibling file with restricted permissions.
- If `cryptography` is not installed, tokens are stored as plain JSON, and
  the only protection is OS file permissions (chmod 600 on POSIX). This is
  NOT strong protection -- anyone with access to the user account or a
  filesystem-level backup can read the file. It is enough to keep other
  *unprivileged* local users out, nothing more. On Windows, chmod has no
  real effect; without `cryptography` there is no meaningful protection
  there today. This is called out in the GUI (Part 4) so the host can make
  an informed choice, e.g. `pip install cryptography` for real encryption.
"""

import json
import os
import stat
import threading
from pathlib import Path

import src.state as state
from src.deps import HAS_CRYPTOGRAPHY

_STORE_PATH = state._CONFIG_DIR / "cloud_tokens.dat"
_KEY_PATH = state._CONFIG_DIR / "cloud_tokens.key"


def _restrict_permissions(path: Path):
    try:
        if os.name != "nt":
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)   # 0o600, owner only
    except OSError:
        pass


class TokenStore:
    """
    Layout: { "<provider_id>": { "<account_id>": {token blob + "label"} } }
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._fernet = self._load_or_create_fernet() if HAS_CRYPTOGRAPHY else None

    @staticmethod
    def _load_or_create_fernet():
        from cryptography.fernet import Fernet
        state._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if _KEY_PATH.exists():
            key = _KEY_PATH.read_bytes()
        else:
            key = Fernet.generate_key()
            _KEY_PATH.write_bytes(key)
            _restrict_permissions(_KEY_PATH)
        return Fernet(key)

    @property
    def encrypted(self) -> bool:
        return self._fernet is not None

    # Read / write whole store

    def _read_all(self) -> dict:
        if not _STORE_PATH.exists():
            return {}
        try:
            raw = _STORE_PATH.read_bytes()
            if self._fernet is not None:
                raw = self._fernet.decrypt(raw)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            # Corrupt or undecryptable store -- fail safe to "no accounts"
            # rather than crash the server on startup.
            return {}

    def _write_all(self, data: dict):
        state._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        if self._fernet is not None:
            payload = self._fernet.encrypt(payload)
        tmp = _STORE_PATH.with_suffix(".tmp")
        tmp.write_bytes(payload)
        tmp.replace(_STORE_PATH)
        _restrict_permissions(_STORE_PATH)

    # Public API

    def get(self, provider_id: str, account_id: str) -> dict | None:
        with self._lock:
            return self._read_all().get(provider_id, {}).get(account_id)

    def set(self, provider_id: str, account_id: str, token_data: dict):
        with self._lock:
            data = self._read_all()
            data.setdefault(provider_id, {})[account_id] = token_data
            self._write_all(data)

    def delete(self, provider_id: str, account_id: str) -> bool:
        with self._lock:
            data = self._read_all()
            removed = data.get(provider_id, {}).pop(account_id, None) is not None
            if removed:
                self._write_all(data)
            return removed

    def list_accounts(self, provider_id: str | None = None) -> list[dict]:
        """Metadata only (id + label), never raw tokens -- safe to hand to the GUI."""
        with self._lock:
            data = self._read_all()
        out = []
        providers = [provider_id] if provider_id else list(data.keys())
        for pid in providers:
            for account_id, blob in data.get(pid, {}).items():
                out.append({
                    "provider_id": pid,
                    "account_id": account_id,
                    "label": blob.get("label", account_id),
                })
        return out


_store: TokenStore | None = None
_store_lock = threading.Lock()


def get_store() -> TokenStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = TokenStore()
        return _store
