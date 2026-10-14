"""Standalone TLS identity for Server-to-Player transports.

This module deliberately shares only the cluster secure-storage primitives.
Its CA, keys, certificates, metadata and secret names are independent from the
Master-Slave mTLS identity.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import ssl
import threading
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .cluster.identity import certificate_fingerprint
from .cluster.key_store import (
    SecureKeyBackend,
    SecureStorageUnavailable,
    default_backend,
)

CA_VALID_DAYS = 10 * 365
LEAF_VALID_DAYS = 397
LEAF_RENEW_BEFORE_DAYS = 30
CA_PASSWORD_NAME = "server-player-tls-ca-pkcs8-password-v1"
LEAF_PASSWORD_NAME = "server-player-tls-leaf-pkcs8-password-v1"
ECDSA_PASSWORD_NAME = "server-player-tls-ecdsa-pkcs8-password-v1"
TLS_CONFIG_FILENAME = "server_player_tls.json"
TLS_ENVIRONMENT_VARIABLE = "NETSHARE_TLS_ENABLED"

_runtime_lock = threading.RLock()
_transport_tls_active = False


@dataclass(frozen=True)
class ServerTlsIdentity:
    server_id: str
    ca_certificate_path: Path
    leaf_certificate_path: Path
    leaf_private_key_path: Path
    leaf_private_key_password: bytes
    ecdsa_certificate_path: Path
    ecdsa_private_key_path: Path
    ecdsa_private_key_password: bytes
    ca_fingerprint: str


def _parse_enabled(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def tls_environment_override() -> bool | None:
    """Return the environment-forced TLS value, or ``None`` when user controlled."""
    environment = os.environ.get(TLS_ENVIRONMENT_VARIABLE)
    return None if environment is None else _parse_enabled(environment)


def _persisted_tls_enabled(config_dir: Path) -> bool:
    path = Path(config_dir) / TLS_CONFIG_FILENAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return _parse_enabled(payload.get("enabled"))
    except FileNotFoundError:
        return False
    except (OSError, ValueError, AttributeError) as error:
        raise SecureStorageUnavailable("Server-Player TLS config is invalid") from error


def tls_enabled(config_dir: Path) -> bool:
    """Read the effective TLS toggle, defaulting safely to clear/off."""
    override = tls_environment_override()
    return _persisted_tls_enabled(config_dir) if override is None else override


def tls_settings_snapshot(config_dir: Path) -> dict[str, object]:
    override = tls_environment_override()
    persisted = _persisted_tls_enabled(config_dir)
    effective = persisted if override is None else override
    return {
        "enabled": bool(effective),
        "persisted_enabled": bool(persisted),
        "active": is_transport_tls_active(),
        "read_only": override is not None,
        "environment_override": override,
        "environment_variable": TLS_ENVIRONMENT_VARIABLE if override is not None else None,
    }


def save_tls_enabled(config_dir: Path, enabled: bool) -> None:
    path = Path(config_dir) / TLS_CONFIG_FILENAME
    _atomic_write(path, json.dumps(
        {"enabled": bool(enabled)}, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8"))


def set_transport_tls_active(active: bool) -> None:
    global _transport_tls_active
    with _runtime_lock:
        _transport_tls_active = bool(active)


def is_transport_tls_active() -> bool:
    with _runtime_lock:
        return _transport_tls_active




def certificate_spki_sha256(certificate: x509.Certificate) -> str:
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def tls_identity_descriptor(config_dir: Path, server_id: str) -> dict[str, object] | None:
    directory = Path(config_dir) / "server_player_tls"
    try:
        metadata = json.loads((directory / "identity.json").read_text(encoding="utf-8"))
        if str(metadata["server_id"]) != str(server_id):
            raise ValueError("stored TLS identity belongs to another server")
        leaves = [
            x509.load_pem_x509_certificate((directory / "server_cert.pem").read_bytes()),
            x509.load_pem_x509_certificate((directory / "server_ecdsa_cert.pem").read_bytes()),
        ]
        ca = x509.load_pem_x509_certificate((directory / "ca_cert.pem").read_bytes())
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return {
        "version": 1,
        "leaf_spki_sha256": sorted({certificate_spki_sha256(cert) for cert in leaves}),
        "ca_fingerprint": certificate_fingerprint(ca),
    }

def _atomic_write(path: Path, value: bytes, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(value)
    if private:
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
    os.replace(temporary, path)


class ServerTlsIdentityStore:
    """Create and renew a CA-pinned TLS identity for HTTP and WebSocket."""

    def __init__(
        self, config_dir: Path, backend: SecureKeyBackend | None = None, now=None,
    ):
        self.directory = Path(config_dir) / "server_player_tls"
        self.backend = backend or default_backend(Path(config_dir))
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.metadata_path = self.directory / "identity.json"
        self.ca_cert_path = self.directory / "ca_cert.pem"
        self.ca_key_path = self.directory / "ca_key.pem.enc"
        self.leaf_cert_path = self.directory / "server_cert.pem"
        self.leaf_key_path = self.directory / "server_key.pem.enc"
        self.ecdsa_cert_path = self.directory / "server_ecdsa_cert.pem"
        self.ecdsa_key_path = self.directory / "server_ecdsa_key.pem.enc"

    def exists(self) -> bool:
        return all(path.exists() for path in (
            self.metadata_path, self.ca_cert_path, self.ca_key_path,
            self.leaf_cert_path, self.leaf_key_path,
        ))

    def ensure_identity(self, server_id: str) -> ServerTlsIdentity:
        server_id = str(server_id).strip()
        if not server_id or len(server_id) > 128:
            raise ValueError("invalid server identity")
        if not self.exists():
            self._create(server_id)
        if not self._ecdsa_exists():
            self._create_ecdsa_leaf(server_id)
        identity = self.load_identity(server_id)
        if self.leaf_certificate_needs_renewal(self.leaf_cert_path):
            self._renew_leaf(server_id, algorithm="ed25519")
            identity = self.load_identity(server_id)
        if self.leaf_certificate_needs_renewal(self.ecdsa_cert_path):
            self._renew_leaf(server_id, algorithm="ecdsa")
            identity = self.load_identity(server_id)
        return identity

    def load_identity(self, expected_server_id: str | None = None) -> ServerTlsIdentity:
        try:
            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            server_id = str(metadata["server_id"])
            ca = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            leaf = x509.load_pem_x509_certificate(self.leaf_cert_path.read_bytes())
            ecdsa_leaf = x509.load_pem_x509_certificate(
                self.ecdsa_cert_path.read_bytes()
            )
            ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)
            ca.public_key().verify(
                ecdsa_leaf.signature, ecdsa_leaf.tbs_certificate_bytes
            )
            for certificate in (leaf, ecdsa_leaf):
                sans = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.UniformResourceIdentifier)
                if sans != [f"urn:netshare:server:{server_id}"]:
                    raise ValueError("server certificate identity mismatch")
            if not isinstance(leaf.public_key(), Ed25519PublicKey):
                raise ValueError("Server-Player Ed25519 leaf is invalid")
            ecdsa_public = ecdsa_leaf.public_key()
            if not isinstance(ecdsa_public, ec.EllipticCurvePublicKey) or not isinstance(
                ecdsa_public.curve, ec.SECP256R1
            ):
                raise ValueError("Server-Player ECDSA leaf is invalid")
            if expected_server_id is not None and server_id != expected_server_id:
                raise ValueError("stored TLS identity belongs to another server")
        except (OSError, ValueError, KeyError, TypeError, x509.ExtensionNotFound) as error:
            raise SecureStorageUnavailable("Server-Player TLS identity is invalid") from error
        leaf_password = self._required_secret(LEAF_PASSWORD_NAME)
        ecdsa_password = self._required_secret(ECDSA_PASSWORD_NAME)
        try:
            leaf_private = serialization.load_pem_private_key(
                self.leaf_key_path.read_bytes(), password=leaf_password,
            )
            ecdsa_private = serialization.load_pem_private_key(
                self.ecdsa_key_path.read_bytes(), password=ecdsa_password,
            )
            if leaf_private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            ) != leaf.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            ):
                raise ValueError("Server-Player Ed25519 key/certificate mismatch")
            if ecdsa_private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            ) != ecdsa_leaf.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            ):
                raise ValueError("Server-Player ECDSA key/certificate mismatch")
        except (OSError, ValueError, TypeError) as error:
            raise SecureStorageUnavailable("Server-Player TLS private identity is invalid") from error
        return ServerTlsIdentity(
            server_id=server_id,
            ca_certificate_path=self.ca_cert_path,
            leaf_certificate_path=self.leaf_cert_path,
            leaf_private_key_path=self.leaf_key_path,
            leaf_private_key_password=leaf_password,
            ecdsa_certificate_path=self.ecdsa_cert_path,
            ecdsa_private_key_path=self.ecdsa_key_path,
            ecdsa_private_key_password=ecdsa_password,
            ca_fingerprint=certificate_fingerprint(ca),
        )

    def leaf_certificate_needs_renewal(self, certificate_path: Path) -> bool:
        try:
            certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        except (OSError, ValueError) as error:
            raise SecureStorageUnavailable("Server-Player TLS certificate is unavailable") from error
        return certificate.not_valid_after_utc <= (
            self.now() + timedelta(days=LEAF_RENEW_BEFORE_DAYS)
        )

    def _ecdsa_exists(self) -> bool:
        return self.ecdsa_cert_path.exists() and self.ecdsa_key_path.exists()

    def _create(self, server_id: str) -> None:
        if any(self.directory.iterdir()) if self.directory.exists() else False:
            raise SecureStorageUnavailable("incomplete Server-Player TLS identity exists")
        ca_key = Ed25519PrivateKey.generate()
        leaf_key = Ed25519PrivateKey.generate()
        ca_password = secrets.token_hex(32).encode("ascii")
        leaf_password = secrets.token_hex(32).encode("ascii")
        self.backend.store(CA_PASSWORD_NAME, ca_password)
        self.backend.store(LEAF_PASSWORD_NAME, leaf_password)
        ca = self._build_ca(ca_key, server_id)
        leaf = self._build_leaf(leaf_key.public_key(), server_id, ca_key, ca)
        _atomic_write(self.ca_key_path, ca_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(ca_password),
        ), private=True)
        _atomic_write(self.leaf_key_path, leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(leaf_password),
        ), private=True)
        _atomic_write(self.ca_cert_path, ca.public_bytes(serialization.Encoding.PEM))
        _atomic_write(self.leaf_cert_path, leaf.public_bytes(serialization.Encoding.PEM))
        _atomic_write(self.metadata_path, json.dumps({
            "server_id": server_id,
            "ca_fingerprint": certificate_fingerprint(ca),
        }, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        self._create_ecdsa_leaf(server_id)

    def _create_ecdsa_leaf(self, server_id: str) -> None:
        try:
            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            if str(metadata["server_id"]) != server_id:
                raise ValueError("stored TLS identity belongs to another server")
            ca_password = self._required_secret(CA_PASSWORD_NAME)
            ca_key = serialization.load_pem_private_key(
                self.ca_key_path.read_bytes(), password=ca_password,
            )
            ca = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise SecureStorageUnavailable(
                "Server-Player TLS CA is unavailable for ECDSA migration"
            ) from error
        password = secrets.token_hex(32).encode("ascii")
        key = ec.generate_private_key(ec.SECP256R1())
        self.backend.store(ECDSA_PASSWORD_NAME, password)
        certificate = self._build_leaf(key.public_key(), server_id, ca_key, ca)
        _atomic_write(self.ecdsa_key_path, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        ), private=True)
        _atomic_write(
            self.ecdsa_cert_path,
            certificate.public_bytes(serialization.Encoding.PEM),
        )

    def _renew_leaf(self, server_id: str, *, algorithm: str) -> None:
        try:
            ca_password = self._required_secret(CA_PASSWORD_NAME)
            ca_key = serialization.load_pem_private_key(
                self.ca_key_path.read_bytes(), password=ca_password,
            )
            password_name, key_path, cert_path = (
                (LEAF_PASSWORD_NAME, self.leaf_key_path, self.leaf_cert_path)
                if algorithm == "ed25519" else
                (ECDSA_PASSWORD_NAME, self.ecdsa_key_path, self.ecdsa_cert_path)
            )
            leaf_password = self._required_secret(password_name)
            leaf_key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=leaf_password,
            )
            ca = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        except (OSError, ValueError, TypeError) as error:
            raise SecureStorageUnavailable("Server-Player TLS renewal key is unavailable") from error
        leaf = self._build_leaf(leaf_key.public_key(), server_id, ca_key, ca)
        _atomic_write(cert_path, leaf.public_bytes(serialization.Encoding.PEM))

    def _required_secret(self, name: str) -> bytes:
        secret = self.backend.load(name)
        if secret is None or len(secret) != 64:
            raise SecureStorageUnavailable("Server-Player TLS key password is unavailable")
        return secret

    def _build_ca(self, key, server_id: str) -> x509.Certificate:
        now = self.now()
        name = x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, f"NetShare Player CA {server_id}",
        )])
        return (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=CA_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ), critical=True).sign(key, algorithm=None))

    def _build_leaf(self, public_key, server_id: str, ca_key, ca) -> x509.Certificate:
        now = self.now()
        return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(
                NameOID.COMMON_NAME, f"NetShare Server {server_id}",
            )])).issuer_name(ca.subject).public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=LEAF_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(f"urn:netshare:server:{server_id}"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1")),
            ]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]), critical=False).sign(ca_key, algorithm=None))


def server_ssl_context(identity: ServerTlsIdentity) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(
        certfile=str(identity.leaf_certificate_path),
        keyfile=str(identity.leaf_private_key_path),
        password=identity.leaf_private_key_password,
    )
    context.load_cert_chain(
        certfile=str(identity.ecdsa_certificate_path),
        keyfile=str(identity.ecdsa_private_key_path),
        password=identity.ecdsa_private_key_password,
    )
    _install_certificate_trace(context, identity)
    return context


def _install_certificate_trace(
    context: ssl.SSLContext, identity: ServerTlsIdentity,
) -> None:
    """Log the leaf selected by OpenSSL without influencing negotiation."""
    if not hasattr(context, "_msg_callback"):
        return
    ed25519 = x509.load_pem_x509_certificate(
        identity.leaf_certificate_path.read_bytes()
    ).public_bytes(serialization.Encoding.DER)
    ecdsa = x509.load_pem_x509_certificate(
        identity.ecdsa_certificate_path.read_bytes()
    ).public_bytes(serialization.Encoding.DER)

    def trace(connection, direction, _version, _content_type, message_type, data):
        if direction != "write" or getattr(message_type, "name", "") != "CERTIFICATE":
            return
        payload = bytes(data)
        certificate_type = (
            "ed25519" if ed25519 in payload else
            "ecdsa_p256" if ecdsa in payload else
            "unknown"
        )
        try:
            peer = connection.getpeername()
            remote = f"{peer[0]}:{peer[1]}"
        except (AttributeError, OSError, TypeError):
            remote = "unknown"
        from src import state
        state._emit(
            f"TLS certificate negotiated peer={remote} key={certificate_type}",
            "debug",
        )

    context._msg_callback = trace
