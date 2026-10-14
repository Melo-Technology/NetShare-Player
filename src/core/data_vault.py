"""NetShare Data Vault primitives.

C5.1 provides authenticated encryption at rest for sensitive *internal* server
state. Shared media files are deliberately outside this vault.

The vault uses one random 256-bit data-encryption key (DEK). The DEK is wrapped
rather than derived directly from a user password, allowing password changes to
rewrap a few bytes instead of re-encrypting all protected data.
"""

from __future__ import annotations

import base64
from contextlib import closing
import ctypes
import hashlib
import importlib
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

VAULT_VERSION = 1
FILE_MAGIC = b"NSVAULT1\x00"
DEK_BYTES = 32
NONCE_BYTES = 12
SALT_BYTES = 16
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_KIB = 64 * 1024

# 16×16 unambiguous code-word pairs encode 128 bits as sixteen tokens.
# The phrase is generated once and never persisted; only a recovery-wrapped DEK
# and a random KDF salt are stored.
_RECOVERY_LEFT = (
    "amber", "birch", "cobalt", "dune", "ember", "frost", "grove", "harbor",
    "iris", "juniper", "kepler", "lumen", "maple", "nova", "opal", "prairie",
)
_RECOVERY_RIGHT = (
    "arch", "beacon", "cedar", "delta", "echo", "falcon", "garden", "horizon",
    "island", "jasmine", "kite", "lantern", "meadow", "north", "orbit", "pearl",
)


def _recovery_phrase() -> str:
    raw = secrets.token_bytes(16)
    return " ".join(
        f"{_RECOVERY_LEFT[(byte >> 4) & 0x0F]}-{_RECOVERY_RIGHT[byte & 0x0F]}"
        for byte in raw
    )


def _normalize_recovery_phrase(value: str) -> str:
    tokens = [part.strip().lower() for part in str(value or "").replace("\n", " ").split() if part.strip()]
    if len(tokens) != 16:
        raise VaultAuthenticationError("vault_recovery_key_invalid")
    allowed = {f"{left}-{right}" for left in _RECOVERY_LEFT for right in _RECOVERY_RIGHT}
    if any(token not in allowed for token in tokens):
        raise VaultAuthenticationError("vault_recovery_key_invalid")
    return " ".join(tokens)


class VaultError(RuntimeError):
    """Base class for bounded, user-presentable vault errors."""


class VaultLockedError(VaultError):
    pass


class VaultAuthenticationError(VaultError):
    pass


class VaultCorruptedError(VaultError):
    pass


class VaultUnavailableError(VaultError):
    pass


@dataclass(frozen=True)
class VaultStatus:
    configured: bool
    mode: str
    unlocked: bool
    remember_on_windows: bool = False
    recovery_enabled: bool = False


class OsKeyProtector:
    """Protect small vault secrets with the current operating-system account.

    Windows keeps the C5.1 DPAPI implementation unchanged. macOS and Linux
    store a random OS-wrapping key (KEK) in the platform credential store and
    use that KEK only to wrap the small secret handled by this protector.

    This does *not* alter the Data Vault payload format or the password-mode
    Argon2id KEK/DEK architecture. There is deliberately no plaintext fallback.
    """

    SERVICE = "com.melotechnology.netshare.vault"
    _OS_ENVELOPE_MAGIC = b"NSOSKEY1\x00"
    _OS_ENVELOPE_AAD_PREFIX = b"netshare:data-vault:os-key-protector:v1:"
    _PROBE_PREFIX = "probe-"

    def __init__(self, config_dir: Path | None = None):
        self.config_dir = Path(config_dir) if config_dir is not None else None
        identity = str(self.config_dir.resolve()) if self.config_dir is not None else "default"
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
        self.account = f"vault-kek-{digest}"

    def protect(self, data: bytes) -> bytes:
        payload = bytes(data)
        if os.name == "nt":
            # C5.1 compatibility contract: raw DPAPI blob, unchanged.
            return self._crypt(payload, protect=True)
        if sys.platform == "darwin":
            return self._wrap_with_platform_kek(payload, self._macos_get_kek(create=True))
        if sys.platform.startswith("linux"):
            return self._wrap_with_platform_kek(payload, self._linux_get_kek(create=True))
        raise VaultUnavailableError("os_protection_unsupported")

    def unprotect(self, data: bytes) -> bytes:
        payload = bytes(data)
        if os.name == "nt":
            # C5.1 compatibility contract: raw DPAPI blob, unchanged.
            return self._crypt(payload, protect=False)
        if sys.platform == "darwin":
            return self._unwrap_with_platform_kek(payload, self._macos_get_kek(create=False))
        if sys.platform.startswith("linux"):
            return self._unwrap_with_platform_kek(payload, self._linux_get_kek(create=False))
        raise VaultUnavailableError("os_protection_unsupported")

    def probe_available(self) -> bool:
        """Perform a real write/read/delete probe for the active OS backend.

        A simple platform/import check is intentionally insufficient: Linux
        may have no D-Bus session/Secret Service daemon, and Keychain access on
        macOS can fail at runtime. The temporary probe secret is always deleted
        on a best-effort basis.
        """
        sample = secrets.token_bytes(32)
        if os.name == "nt":
            try:
                return self._crypt(self._crypt(sample, protect=True), protect=False) == sample
            except Exception:
                return False

        account = f"{self._PROBE_PREFIX}{secrets.token_hex(16)}"
        if sys.platform == "darwin":
            try:
                self._macos_store_secret(account, sample)
                return self._macos_read_secret(account) == sample
            except Exception:
                return False
            finally:
                try:
                    self._macos_delete_secret(account)
                except Exception:
                    pass

        if sys.platform.startswith("linux"):
            try:
                self._linux_store_secret(account, sample)
                return self._linux_read_secret(account) == sample
            except Exception:
                return False
            finally:
                try:
                    self._linux_delete_secret(account)
                except Exception:
                    pass
        return False

    def _wrap_with_platform_kek(self, data: bytes, kek: bytes) -> bytes:
        if len(kek) != DEK_BYTES:
            raise VaultUnavailableError("os_key_material_invalid")
        nonce = secrets.token_bytes(NONCE_BYTES)
        aad = self._OS_ENVELOPE_AAD_PREFIX + self.account.encode("utf-8")
        ciphertext = AESGCM(kek).encrypt(nonce, data, aad)
        return self._OS_ENVELOPE_MAGIC + nonce + ciphertext

    def _unwrap_with_platform_kek(self, payload: bytes, kek: bytes) -> bytes:
        minimum = len(self._OS_ENVELOPE_MAGIC) + NONCE_BYTES + 16
        if len(payload) < minimum or not payload.startswith(self._OS_ENVELOPE_MAGIC):
            raise VaultCorruptedError("vault_os_key_format_invalid")
        nonce_start = len(self._OS_ENVELOPE_MAGIC)
        nonce = payload[nonce_start:nonce_start + NONCE_BYTES]
        ciphertext = payload[nonce_start + NONCE_BYTES:]
        aad = self._OS_ENVELOPE_AAD_PREFIX + self.account.encode("utf-8")
        try:
            return AESGCM(kek).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise VaultAuthenticationError("vault_os_key_unwrap_failed") from exc

    # ---- macOS Keychain -------------------------------------------------

    @staticmethod
    def _macos_modules():
        try:
            return importlib.import_module("Security"), importlib.import_module("objc")
        except Exception as exc:
            raise VaultUnavailableError("macos_keychain_dependency_missing") from exc

    def _macos_identifier_query(self, account: str) -> tuple[object, dict]:
        Security, _objc = self._macos_modules()
        query = {
            Security.kSecClass: Security.kSecClassGenericPassword,
            Security.kSecAttrService: self.SERVICE,
            Security.kSecAttrAccount: account,
        }
        # Apple documents that kSecAttrAccessible applies to generic-password
        # items on macOS when the Data Protection Keychain is selected.
        if hasattr(Security, "kSecUseDataProtectionKeychain"):
            query[Security.kSecUseDataProtectionKeychain] = True
        return Security, query

    def _macos_read_secret(self, account: str) -> bytes | None:
        Security, query = self._macos_identifier_query(account)
        read_query = dict(query)
        read_query[Security.kSecReturnData] = True
        read_query[Security.kSecMatchLimit] = Security.kSecMatchLimitOne
        try:
            result = Security.SecItemCopyMatching(read_query, None)
        except Exception as exc:
            raise VaultUnavailableError("macos_keychain_operation_failed") from exc
        if isinstance(result, tuple):
            status, value = result[0], result[1]
        else:  # defensive guard for bridge metadata differences
            status, value = result, None
        if status == Security.errSecItemNotFound:
            return None
        if status != Security.errSecSuccess or value is None:
            raise VaultUnavailableError("macos_keychain_operation_failed")
        try:
            return bytes(value)
        except Exception as exc:
            raise VaultUnavailableError("macos_keychain_operation_failed") from exc

    def _macos_store_secret(self, account: str, secret: bytes) -> None:
        Security, query = self._macos_identifier_query(account)
        updates = {
            Security.kSecValueData: bytes(secret),
            Security.kSecAttrAccessible: Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        }
        try:
            status = Security.SecItemUpdate(query, updates)
            if status == Security.errSecItemNotFound:
                add_query = dict(query)
                add_query.update(updates)
                status = Security.SecItemAdd(add_query, self._macos_modules()[1].NULL)
            if isinstance(status, tuple):
                status = status[0]
        except Exception as exc:
            raise VaultUnavailableError("macos_keychain_operation_failed") from exc
        if status != Security.errSecSuccess:
            raise VaultUnavailableError("macos_keychain_operation_failed")

    def _macos_delete_secret(self, account: str) -> None:
        Security, query = self._macos_identifier_query(account)
        try:
            status = Security.SecItemDelete(query)
        except Exception as exc:
            raise VaultUnavailableError("macos_keychain_operation_failed") from exc
        if status not in (Security.errSecSuccess, Security.errSecItemNotFound):
            raise VaultUnavailableError("macos_keychain_operation_failed")

    def _macos_get_kek(self, *, create: bool) -> bytes:
        existing = self._macos_read_secret(self.account)
        if existing is not None:
            if len(existing) != DEK_BYTES:
                raise VaultUnavailableError("os_key_material_invalid")
            return existing
        if not create:
            raise VaultUnavailableError("macos_keychain_key_missing")
        kek = secrets.token_bytes(DEK_BYTES)
        self._macos_store_secret(self.account, kek)
        return kek

    # ---- Linux Secret Service ------------------------------------------

    @staticmethod
    def _linux_secretstorage():
        try:
            return importlib.import_module("secretstorage")
        except Exception as exc:
            raise VaultUnavailableError("linux_secret_service_dependency_missing") from exc

    def _linux_collection(self, secretstorage, connection):
        try:
            # get_default_collection() may create a collection and prompt. A
            # server startup/probe must never trigger that UI, so resolve the
            # existing default alias only and fail closed if it is absent.
            collection = secretstorage.get_collection_by_alias(connection, "default")
            if collection.is_locked():
                # NetShare Server must not block startup with a desktop prompt.
                raise VaultUnavailableError("linux_secret_service_locked")
            return collection
        except VaultUnavailableError:
            raise
        except secretstorage.ItemNotFoundException as exc:
            raise VaultUnavailableError("linux_secret_service_collection_missing") from exc
        except secretstorage.SecretServiceNotAvailableException as exc:
            raise VaultUnavailableError("linux_secret_service_unavailable") from exc
        except secretstorage.LockedException as exc:
            raise VaultUnavailableError("linux_secret_service_locked") from exc
        except secretstorage.SecretStorageException as exc:
            raise VaultUnavailableError("linux_secret_service_operation_failed") from exc

    def _linux_with_collection(self, operation):
        secretstorage = self._linux_secretstorage()
        try:
            connection = secretstorage.dbus_init()
        except secretstorage.SecretServiceNotAvailableException as exc:
            raise VaultUnavailableError("linux_secret_service_unavailable") from exc
        except secretstorage.SecretStorageException as exc:
            raise VaultUnavailableError("linux_secret_service_operation_failed") from exc
        except Exception as exc:
            # Covers a missing/unusable session bus in minimal/headless setups
            # without leaking a raw D-Bus exception through DesktopApi.
            raise VaultUnavailableError("linux_secret_service_unavailable") from exc
        with closing(connection):
            collection = self._linux_collection(secretstorage, connection)
            try:
                return operation(secretstorage, collection)
            except VaultUnavailableError:
                raise
            except secretstorage.SecretServiceNotAvailableException as exc:
                raise VaultUnavailableError("linux_secret_service_unavailable") from exc
            except secretstorage.LockedException as exc:
                raise VaultUnavailableError("linux_secret_service_locked") from exc
            except secretstorage.PromptDismissedException as exc:
                raise VaultUnavailableError("linux_secret_service_locked") from exc
            except secretstorage.SecretStorageException as exc:
                raise VaultUnavailableError("linux_secret_service_operation_failed") from exc

    def _linux_attributes(self, account: str) -> dict[str, str]:
        return {"application": self.SERVICE, "account": account}

    def _linux_read_secret(self, account: str) -> bytes | None:
        def read(_secretstorage, collection):
            items = list(collection.search_items(self._linux_attributes(account)))
            if not items:
                return None
            item = items[0]
            if item.is_locked():
                raise VaultUnavailableError("linux_secret_service_locked")
            return bytes(item.get_secret())
        return self._linux_with_collection(read)

    def _linux_store_secret(self, account: str, secret: bytes) -> None:
        def write(_secretstorage, collection):
            collection.create_item(
                "NetShare Data Vault",
                self._linux_attributes(account),
                bytes(secret),
                replace=True,
                content_type="application/octet-stream",
            )
            return None
        self._linux_with_collection(write)

    def _linux_delete_secret(self, account: str) -> None:
        def delete(_secretstorage, collection):
            for item in list(collection.search_items(self._linux_attributes(account))):
                if item.is_locked():
                    raise VaultUnavailableError("linux_secret_service_locked")
                item.delete()
            return None
        self._linux_with_collection(delete)

    def _linux_get_kek(self, *, create: bool) -> bytes:
        existing = self._linux_read_secret(self.account)
        if existing is not None:
            if len(existing) != DEK_BYTES:
                raise VaultUnavailableError("os_key_material_invalid")
            return existing
        if not create:
            raise VaultUnavailableError("linux_secret_service_key_missing")
        kek = secrets.token_bytes(DEK_BYTES)
        self._linux_store_secret(self.account, kek)
        return kek

    @staticmethod
    def _crypt(data: bytes, *, protect: bool) -> bytes:
        """C5.1 Windows DPAPI implementation — intentionally unchanged."""
        if os.name != "nt":
            raise VaultUnavailableError("windows_dpapi_unavailable")

        class DataBlob(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.c_uint32),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ]

        source_buffer = ctypes.create_string_buffer(data)
        source = DataBlob(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        target = DataBlob()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        # CRYPTPROTECT_UI_FORBIDDEN: never show an OS UI from server startup.
        if not function(ctypes.byref(source), None, None, None, None, 0x01, ctypes.byref(target)):
            raise VaultUnavailableError("windows_dpapi_operation_failed")
        try:
            return ctypes.string_at(target.pbData, target.cbData)
        finally:
            kernel32.LocalFree(target.pbData)


_OS_PROTECTION_PROBE_TTL_SECONDS = 30.0
_OS_PROTECTION_PROBE_LOCK = threading.Lock()
_OS_PROTECTION_PROBE_CACHE: dict[str, tuple[float, bool]] = {}


def os_protection_available(config_dir: Path, *, force: bool = False) -> bool:
    """Return the result of a bounded real backend probe, cached briefly."""
    key = f"{os.name}:{sys.platform}:{Path(config_dir).resolve()}"
    now = time.monotonic()
    with _OS_PROTECTION_PROBE_LOCK:
        cached = _OS_PROTECTION_PROBE_CACHE.get(key)
        if not force and cached is not None and now - cached[0] < _OS_PROTECTION_PROBE_TTL_SECONDS:
            return cached[1]
    available = OsKeyProtector(config_dir).probe_available()
    with _OS_PROTECTION_PROBE_LOCK:
        _OS_PROTECTION_PROBE_CACHE[key] = (now, bool(available))
    return bool(available)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception as exc:  # pragma: no cover - defensive format guard
        raise VaultCorruptedError("vault_metadata_invalid") from exc


def _derive_argon2(secret: str, salt: bytes, *, length: int = 32) -> bytes:
    if not isinstance(secret, str) or not secret:
        raise VaultAuthenticationError("vault_secret_required")
    kdf = Argon2id(
        salt=salt,
        length=length,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_KIB,
    )
    return kdf.derive(secret.encode("utf-8"))


def _wrap_dek(dek: bytes, kek: bytes, *, aad: bytes) -> dict[str, str]:
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(kek).encrypt(nonce, dek, aad)
    return {"nonce": _b64(nonce), "ciphertext": _b64(ciphertext)}


def _unwrap_dek(record: dict, kek: bytes, *, aad: bytes) -> bytes:
    try:
        dek = AESGCM(kek).decrypt(_unb64(record["nonce"]), _unb64(record["ciphertext"]), aad)
    except Exception as exc:
        raise VaultAuthenticationError("vault_unlock_failed") from exc
    if len(dek) != DEK_BYTES:
        raise VaultCorruptedError("vault_dek_invalid")
    return dek


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


class DataVault:
    """Versioned DEK vault plus AES-GCM file/bytes helpers."""

    METADATA_NAME = "data_vault.json"
    OS_KEY_NAME = "data_vault_key.dpapi"
    REMEMBERED_KEY_NAME = "data_vault_remembered.dpapi"

    def __init__(self, config_dir: Path, *, os_protector: OsKeyProtector | None = None):
        self.config_dir = Path(config_dir)
        self.metadata_path = self.config_dir / self.METADATA_NAME
        self.os_key_path = self.config_dir / self.OS_KEY_NAME
        self.remembered_key_path = self.config_dir / self.REMEMBERED_KEY_NAME
        self.os_protector = os_protector or OsKeyProtector(self.config_dir)
        self._dek: bytearray | None = None
        self._lock = threading.RLock()

    def _load_metadata(self) -> dict:
        if not self.metadata_path.exists():
            return {}
        try:
            data = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise VaultCorruptedError("vault_metadata_invalid") from exc
        if not isinstance(data, dict) or int(data.get("version", 0)) != VAULT_VERSION:
            raise VaultCorruptedError("vault_metadata_version_invalid")
        return data

    def _save_metadata(self, data: dict) -> None:
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        _atomic_write(self.metadata_path, payload)

    @property
    def configured(self) -> bool:
        return self.metadata_path.exists()

    @property
    def unlocked(self) -> bool:
        return self._dek is not None

    @property
    def migration_version(self) -> int:
        if not self.configured:
            return 0
        try:
            return max(0, int(self._load_metadata().get("migration_version") or 0))
        except (TypeError, ValueError):
            return 0

    def mark_migration_complete(self, version: int) -> None:
        with self._lock:
            self._require_dek()
            data = self._load_metadata()
            data["migration_version"] = max(0, int(version))
            self._save_metadata(data)

    @property
    def recovery_decision(self) -> str:
        if not self.configured:
            return "undecided"
        data = self._load_metadata()
        return str((data.get("recovery") or {}).get("decision") or "undecided")

    def status(self) -> VaultStatus:
        data = self._load_metadata() if self.configured else {}
        return VaultStatus(
            configured=self.configured,
            mode=str(data.get("mode") or "unconfigured"),
            unlocked=self.unlocked,
            remember_on_windows=bool(data.get("remember_on_windows", False)),
            recovery_enabled=bool(data.get("recovery", {}).get("wrapped_dek")),
        )

    def configure_os_protected(self) -> None:
        with self._lock:
            if self.configured:
                raise VaultError("vault_already_configured")
            dek = secrets.token_bytes(DEK_BYTES)
            protected = self.os_protector.protect(dek)
            _atomic_write(self.os_key_path, protected)
            self._save_metadata({
                "version": VAULT_VERSION,
                "mode": "os",
                "remember_on_windows": False,
                "recovery": {},
            })
            self._set_dek(dek)

    def configure_password(self, password: str, *, remember_on_windows: bool = False) -> None:
        with self._lock:
            if self.configured:
                raise VaultError("vault_already_configured")
            dek = secrets.token_bytes(DEK_BYTES)
            salt = secrets.token_bytes(SALT_BYTES)
            kek = _derive_argon2(password, salt)
            wrapped = _wrap_dek(dek, kek, aad=b"netshare:data-vault:password:v1")
            self._save_metadata({
                "version": VAULT_VERSION,
                "mode": "password",
                "password": {"salt": _b64(salt), "wrapped_dek": wrapped},
                "remember_on_windows": bool(remember_on_windows),
                "recovery": {},
            })
            if remember_on_windows:
                self._write_remembered_dek(dek)
            self._set_dek(dek)

    def unlock_os(self) -> None:
        with self._lock:
            data = self._load_metadata()
            if data.get("mode") != "os" or not self.os_key_path.exists():
                raise VaultCorruptedError("vault_os_key_missing")
            try:
                dek = self.os_protector.unprotect(self.os_key_path.read_bytes())
            except VaultError:
                raise
            except Exception as exc:
                raise VaultAuthenticationError("vault_unlock_failed") from exc
            self._validate_and_set_dek(dek)

    def unlock_password(self, password: str) -> None:
        with self._lock:
            data = self._load_metadata()
            if data.get("mode") != "password":
                raise VaultAuthenticationError("vault_wrong_mode")
            record = data.get("password") or {}
            salt = _unb64(str(record.get("salt") or ""))
            kek = _derive_argon2(password, salt)
            dek = _unwrap_dek(record.get("wrapped_dek") or {}, kek, aad=b"netshare:data-vault:password:v1")
            self._set_dek(dek)

    def try_unlock_remembered(self) -> bool:
        with self._lock:
            data = self._load_metadata() if self.configured else {}
            if data.get("mode") != "password" or not data.get("remember_on_windows"):
                return False
            if not self.remembered_key_path.exists():
                return False
            try:
                dek = self.os_protector.unprotect(self.remembered_key_path.read_bytes())
                self._validate_and_set_dek(dek)
                return True
            except Exception:
                return False

    def set_remember_on_windows(self, enabled: bool) -> None:
        with self._lock:
            self._require_dek()
            data = self._load_metadata()
            if data.get("mode") != "password":
                raise VaultError("vault_wrong_mode")
            data["remember_on_windows"] = bool(enabled)
            if enabled:
                self._write_remembered_dek(bytes(self._dek or b""))
            else:
                self.remembered_key_path.unlink(missing_ok=True)
            self._save_metadata(data)

    def generate_recovery_key_once(self) -> str:
        """Create the one-time recovery phrase and persist only its DEK wrapper."""
        with self._lock:
            dek = self._require_dek()
            data = self._load_metadata()
            recovery = data.get("recovery") or {}
            if recovery.get("decision") in {"enabled", "skipped"}:
                raise VaultError("vault_recovery_already_decided")
            phrase = _recovery_phrase()
            salt = secrets.token_bytes(SALT_BYTES)
            kek = _derive_argon2(phrase, salt)
            data["recovery"] = {
                "decision": "enabled",
                "salt": _b64(salt),
                "wrapped_dek": _wrap_dek(dek, kek, aad=b"netshare:data-vault:recovery:v1"),
            }
            self._save_metadata(data)
            return phrase

    def skip_recovery_key(self) -> None:
        """Persist an explicit opt-out so the activation UI never loops."""
        with self._lock:
            self._require_dek()
            data = self._load_metadata()
            recovery = data.get("recovery") or {}
            if recovery.get("decision") in {"enabled", "skipped"}:
                raise VaultError("vault_recovery_already_decided")
            data["recovery"] = {"decision": "skipped"}
            self._save_metadata(data)

    def unlock_recovery(self, recovery_phrase: str) -> None:
        with self._lock:
            data = self._load_metadata()
            recovery = data.get("recovery") or {}
            if recovery.get("decision") != "enabled" or not recovery.get("wrapped_dek"):
                raise VaultAuthenticationError("vault_recovery_unavailable")
            phrase = _normalize_recovery_phrase(recovery_phrase)
            salt = _unb64(str(recovery.get("salt") or ""))
            kek = _derive_argon2(phrase, salt)
            dek = _unwrap_dek(
                recovery.get("wrapped_dek") or {},
                kek,
                aad=b"netshare:data-vault:recovery:v1",
            )
            self._set_dek(dek)

    def reset_password_with_recovery(
        self, recovery_phrase: str, new_password: str, *, remember_on_windows: bool = False
    ) -> None:
        """Recover a password-mode vault without creating a support backdoor."""
        with self._lock:
            self.unlock_recovery(recovery_phrase)
            dek = self._require_dek()
            data = self._load_metadata()
            if data.get("mode") != "password":
                raise VaultError("vault_wrong_mode")
            salt = secrets.token_bytes(SALT_BYTES)
            kek = _derive_argon2(new_password, salt)
            data["password"] = {
                "salt": _b64(salt),
                "wrapped_dek": _wrap_dek(dek, kek, aad=b"netshare:data-vault:password:v1"),
            }
            data["remember_on_windows"] = bool(remember_on_windows)
            self._save_metadata(data)
            if remember_on_windows:
                self._write_remembered_dek(dek)
            else:
                self.remembered_key_path.unlink(missing_ok=True)

    def switch_to_os_protected(self, *, current_password: str | None = None) -> None:
        with self._lock:
            data = self._load_metadata()
            if data.get("mode") == "password":
                if not current_password:
                    raise VaultAuthenticationError("vault_current_password_required")
                self.unlock_password(current_password)
            dek = self._require_dek()
            _atomic_write(self.os_key_path, self.os_protector.protect(dek))
            self.remembered_key_path.unlink(missing_ok=True)
            data.pop("password", None)
            data["mode"] = "os"
            data["remember_on_windows"] = False
            self._save_metadata(data)

    def switch_to_password(
        self, new_password: str, *, current_password: str | None = None, remember_on_windows: bool = False
    ) -> None:
        with self._lock:
            data = self._load_metadata()
            if data.get("mode") == "password":
                if not current_password:
                    raise VaultAuthenticationError("vault_current_password_required")
                self.unlock_password(current_password)
            else:
                self._require_dek()
            dek = self._require_dek()
            salt = secrets.token_bytes(SALT_BYTES)
            kek = _derive_argon2(new_password, salt)
            data["mode"] = "password"
            data["password"] = {
                "salt": _b64(salt),
                "wrapped_dek": _wrap_dek(dek, kek, aad=b"netshare:data-vault:password:v1"),
            }
            data["remember_on_windows"] = bool(remember_on_windows)
            self._save_metadata(data)
            self.os_key_path.unlink(missing_ok=True)
            if remember_on_windows:
                self._write_remembered_dek(dek)
            else:
                self.remembered_key_path.unlink(missing_ok=True)

    def change_password(self, current_password: str, new_password: str) -> None:
        with self._lock:
            # Always verify the current password even if the vault is already unlocked.
            self.unlock_password(current_password)
            dek = self._require_dek()
            data = self._load_metadata()
            salt = secrets.token_bytes(SALT_BYTES)
            kek = _derive_argon2(new_password, salt)
            data["password"] = {
                "salt": _b64(salt),
                "wrapped_dek": _wrap_dek(dek, kek, aad=b"netshare:data-vault:password:v1"),
            }
            self._save_metadata(data)
            if data.get("remember_on_windows"):
                self._write_remembered_dek(dek)

    def lock(self) -> None:
        with self._lock:
            if self._dek is not None:
                for i in range(len(self._dek)):
                    self._dek[i] = 0
            self._dek = None

    def _write_remembered_dek(self, dek: bytes) -> None:
        _atomic_write(self.remembered_key_path, self.os_protector.protect(dek))

    def _set_dek(self, dek: bytes) -> None:
        self._validate_and_set_dek(dek)

    def _validate_and_set_dek(self, dek: bytes) -> None:
        if len(dek) != DEK_BYTES:
            raise VaultCorruptedError("vault_dek_invalid")
        self.lock()
        self._dek = bytearray(dek)

    def _require_dek(self) -> bytes:
        if self._dek is None:
            raise VaultLockedError("vault_locked")
        return bytes(self._dek)

    def encrypt_bytes(self, plaintext: bytes, *, purpose: str) -> bytes:
        dek = self._require_dek()
        nonce = secrets.token_bytes(NONCE_BYTES)
        aad = f"netshare:vault:{VAULT_VERSION}:{purpose}".encode("utf-8")
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
        return FILE_MAGIC + nonce + ciphertext

    def decrypt_bytes(self, payload: bytes, *, purpose: str) -> bytes:
        if not payload.startswith(FILE_MAGIC) or len(payload) < len(FILE_MAGIC) + NONCE_BYTES + 16:
            raise VaultCorruptedError("vault_payload_invalid")
        dek = self._require_dek()
        offset = len(FILE_MAGIC)
        nonce = payload[offset:offset + NONCE_BYTES]
        ciphertext = payload[offset + NONCE_BYTES:]
        aad = f"netshare:vault:{VAULT_VERSION}:{purpose}".encode("utf-8")
        try:
            return AESGCM(dek).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise VaultCorruptedError("vault_payload_authentication_failed") from exc

    def encrypt_file(self, source: Path, destination: Path, *, purpose: str) -> None:
        self.write_encrypted(destination, Path(source).read_bytes(), purpose=purpose)

    def write_encrypted(self, destination: Path, plaintext: bytes, *, purpose: str) -> None:
        _atomic_write(Path(destination), self.encrypt_bytes(plaintext, purpose=purpose))

    def read_encrypted(self, source: Path, *, purpose: str) -> bytes:
        return self.decrypt_bytes(Path(source).read_bytes(), purpose=purpose)

    def encrypt_json(self, destination: Path, value, *, purpose: str) -> None:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.write_encrypted(destination, payload, purpose=purpose)

    def decrypt_json(self, source: Path, *, purpose: str):
        try:
            return json.loads(self.read_encrypted(source, purpose=purpose).decode("utf-8"))
        except VaultError:
            raise
        except Exception as exc:
            raise VaultCorruptedError("vault_json_invalid") from exc


def secure_unlink(path: Path, *, passes: int = 1) -> None:
    """Best-effort overwrite then unlink for small sensitive local files.

    SSD wear-leveling means overwrite cannot promise forensic erasure; encryption
    makes DEK destruction the primary purge guarantee. This helper is defense in
    depth for legacy plaintext during migration/reset.
    """
    target = Path(path)
    try:
        if not target.is_file():
            target.unlink(missing_ok=True)
            return
        size = target.stat().st_size
        if size > 0:
            with target.open("r+b", buffering=0) as handle:
                for _ in range(max(1, int(passes))):
                    handle.seek(0)
                    remaining = size
                    while remaining:
                        chunk = secrets.token_bytes(min(1024 * 1024, remaining))
                        handle.write(chunk)
                        remaining -= len(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
        target.unlink(missing_ok=True)
    except FileNotFoundError:
        return


_RUNTIME_LOCK = threading.RLock()
_RUNTIME_VAULT: DataVault | None = None
_RUNTIME_DIR: Path | None = None


def get_data_vault(config_dir: Path) -> DataVault:
    """Return a process-local vault bound to the current config directory."""
    global _RUNTIME_VAULT, _RUNTIME_DIR
    path = Path(config_dir).resolve()
    with _RUNTIME_LOCK:
        if _RUNTIME_VAULT is None or _RUNTIME_DIR != path:
            if _RUNTIME_VAULT is not None:
                _RUNTIME_VAULT.lock()
            _RUNTIME_VAULT = DataVault(path)
            _RUNTIME_DIR = path
        return _RUNTIME_VAULT


def reset_data_vault_runtime_for_tests() -> None:
    global _RUNTIME_VAULT, _RUNTIME_DIR
    with _RUNTIME_LOCK:
        if _RUNTIME_VAULT is not None:
            _RUNTIME_VAULT.lock()
        _RUNTIME_VAULT = None
        _RUNTIME_DIR = None
