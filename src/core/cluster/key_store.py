"""OS-backed storage for the cluster Ed25519 signing key."""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from src.deps import HAS_CRYPTOGRAPHY, HAS_ZEROCONF

KEY_NAME = "master-ed25519-v1"


class SecureStorageUnavailable(RuntimeError):
    """Raised instead of falling back to plaintext key persistence."""


class SecureKeyBackend(ABC):
    @abstractmethod
    def load(self, name: str) -> bytes | None: ...

    @abstractmethod
    def store(self, name: str, secret: bytes) -> None: ...

    @abstractmethod
    def delete(self, name: str) -> None: ...


class MemoryKeyBackend(SecureKeyBackend):
    """Injected deterministic backend for CI; never selected in production."""

    def __init__(self):
        self.values: dict[str, bytes] = {}

    def load(self, name: str) -> bytes | None:
        value = self.values.get(name)
        return bytes(value) if value is not None else None

    def store(self, name: str, secret: bytes) -> None:
        self.values[name] = bytes(secret)

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


class WindowsDpapiBackend(SecureKeyBackend):
    def __init__(self, path: Path):
        self.path = path

    def _path_for(self, name: str) -> Path:
        if name == KEY_NAME:
            return self.path
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:20]
        return self.path.with_name(f"cluster_secret_{digest}.dpapi")

    @staticmethod
    def _crypt(data: bytes, protect: bool) -> bytes:
        if os.name != "nt":
            raise SecureStorageUnavailable("Windows secure storage is unavailable")

        class DataBlob(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.c_uint32),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ]

        buffer = ctypes.create_string_buffer(data)
        source = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        target = DataBlob()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        if not function(
            ctypes.byref(source), None, None, None, None, 0x01, ctypes.byref(target)
        ):
            raise SecureStorageUnavailable("Windows secure storage operation failed")
        try:
            return ctypes.string_at(target.pbData, target.cbData)
        finally:
            kernel32.LocalFree(target.pbData)

    def load(self, name: str) -> bytes | None:
        path = self._path_for(name)
        if not path.exists():
            return None
        return self._crypt(path.read_bytes(), protect=False)

    def store(self, name: str, secret: bytes) -> None:
        path = self._path_for(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(self._crypt(secret, protect=True))
        temporary.replace(path)

    def delete(self, name: str) -> None:
        self._path_for(name).unlink(missing_ok=True)


class MacOSKeychainBackend(SecureKeyBackend):
    SERVICE = "com.melotechnology.netshare.cluster"
    ITEM_NOT_FOUND = -25300

    def __init__(self, security_api=None):
        if sys.platform != "darwin":
            raise SecureStorageUnavailable("macOS Keychain is unavailable")
        try:
            self._security = security_api or ctypes.cdll.LoadLibrary(
                ctypes.util.find_library("Security") or "Security.framework/Security"
            )
            self._core_foundation = ctypes.cdll.LoadLibrary(
                ctypes.util.find_library("CoreFoundation")
                or "CoreFoundation.framework/CoreFoundation"
            )
            self._configure_api()
        except (OSError, AttributeError) as error:
            raise SecureStorageUnavailable("macOS Keychain is unavailable") from error

    def _configure_api(self) -> None:
        self._security.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        self._security.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        self._security.SecKeychainItemDelete.restype = ctypes.c_int32
        self._security.SecKeychainItemFreeContent.restype = ctypes.c_int32
        self._core_foundation.CFRelease.argtypes = [ctypes.c_void_p]

    @staticmethod
    def _text(value: str) -> tuple[bytes, int]:
        encoded = value.encode("utf-8")
        return encoded, len(encoded)

    def _find(self, name: str, include_item: bool = False):
        service, service_length = self._text(self.SERVICE)
        account, account_length = self._text(name)
        secret_length = ctypes.c_uint32()
        secret_pointer = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = self._security.SecKeychainFindGenericPassword(
            None,
            service_length,
            service,
            account_length,
            account,
            ctypes.byref(secret_length),
            ctypes.byref(secret_pointer),
            ctypes.byref(item) if include_item else None,
        )
        return status, secret_length, secret_pointer, item

    def load(self, name: str) -> bytes | None:
        status, length, pointer, _item = self._find(name)
        if status == self.ITEM_NOT_FOUND:
            return None
        if status != 0:
            raise SecureStorageUnavailable("macOS Keychain read failed")
        try:
            return ctypes.string_at(pointer, length.value)
        finally:
            self._security.SecKeychainItemFreeContent(None, pointer)

    def store(self, name: str, secret: bytes) -> None:
        self.delete(name)
        service, service_length = self._text(self.SERVICE)
        account, account_length = self._text(name)
        secret_buffer = ctypes.create_string_buffer(secret)
        status = self._security.SecKeychainAddGenericPassword(
            None,
            service_length,
            service,
            account_length,
            account,
            len(secret),
            secret_buffer,
            None,
        )
        if status != 0:
            raise SecureStorageUnavailable("macOS Keychain write failed")

    def delete(self, name: str) -> None:
        status, _length, pointer, item = self._find(name, include_item=True)
        if status == self.ITEM_NOT_FOUND:
            return
        if status != 0:
            raise SecureStorageUnavailable("macOS Keychain delete failed")
        try:
            if self._security.SecKeychainItemDelete(item) != 0:
                raise SecureStorageUnavailable("macOS Keychain delete failed")
        finally:
            self._security.SecKeychainItemFreeContent(None, pointer)
            self._core_foundation.CFRelease(item)


def default_backend(config_dir: Path) -> SecureKeyBackend:
    if os.name == "nt":
        return WindowsDpapiBackend(config_dir / "cluster_signing_key.dpapi")
    if sys.platform == "darwin":
        return MacOSKeychainBackend()
    raise SecureStorageUnavailable("Secure cluster key storage is unavailable on this platform")


@dataclass(frozen=True)
class ClusterSecurityAvailability:
    available: bool
    reason_code: str = ""


def security_availability(config_dir: Path) -> ClusterSecurityAvailability:
    if not HAS_CRYPTOGRAPHY:
        return ClusterSecurityAvailability(False, "cryptography_missing")
    if not HAS_ZEROCONF:
        return ClusterSecurityAvailability(False, "zeroconf_missing")
    try:
        default_backend(config_dir)
    except SecureStorageUnavailable:
        return ClusterSecurityAvailability(False, "secure_storage_unavailable")
    return ClusterSecurityAvailability(True)


class ClusterKeyStore:
    def __init__(self, backend: SecureKeyBackend):
        if not HAS_CRYPTOGRAPHY:
            raise SecureStorageUnavailable("Ed25519 support is not installed")
        self.backend = backend

    def get_or_create_private_key(self) -> bytes:
        existing = self.backend.load(KEY_NAME)
        if existing is not None:
            if len(existing) != 32:
                raise SecureStorageUnavailable("Stored cluster signing key is invalid")
            return existing
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        secret = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        self.backend.store(KEY_NAME, secret)
        return secret

    def delete_private_key(self) -> None:
        self.backend.delete(KEY_NAME)
