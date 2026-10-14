"""Cluster CA and node certificates without plaintext private-key files."""

from __future__ import annotations

import json
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from .key_store import SecureKeyBackend, SecureStorageUnavailable

CA_VALID_DAYS = 5 * 365
NODE_VALID_DAYS = 90
NODE_RENEW_BEFORE_DAYS = 30
CA_PASSWORD_NAME = "cluster-ca-pkcs8-password-v1"
NODE_PASSWORD_NAME = "cluster-node-pkcs8-password-v1"
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def joined_slave_files_exist(config_dir: Path) -> bool:
    directory = Path(config_dir) / "cluster"
    return (
        all((directory / name).exists() for name in (
            "identity.json", "ca_cert.pem", "node_cert.pem", "node_key.pem.enc",
            "trusted_peers.json", "master_signing_key.bin",
        ))
        and not (directory / "ca_key.pem.enc").exists()
    )


@dataclass(frozen=True)
class ClusterIdentity:
    cluster_id: str
    node_id: str
    ca_certificate_path: Path
    node_certificate_path: Path
    node_private_key_path: Path
    node_private_key_password: bytes
    ca_fingerprint: str


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def _atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(value)
    if path.name.endswith(".pem.enc"):
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
    os.replace(temporary, path)


def _load_certificate(path: Path) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as error:
        raise SecureStorageUnavailable("cluster certificate is unavailable") from error


class ClusterIdentityStore:
    def __init__(self, config_dir: Path, backend: SecureKeyBackend, now=None):
        self.directory = config_dir / "cluster"
        self.backend = backend
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.metadata_path = self.directory / "identity.json"
        self.ca_cert_path = self.directory / "ca_cert.pem"
        self.ca_key_path = self.directory / "ca_key.pem.enc"
        self.node_cert_path = self.directory / "node_cert.pem"
        self.node_key_path = self.directory / "node_key.pem.enc"

    def exists(self, role: str | None = None) -> bool:
        """Return whether a complete identity exists for the requested role.

        A joined Slave deliberately has no cluster CA private key.  Its identity
        is complete only when the Master's trust record and ticket-verification
        key have also been installed.
        """
        common = all(path.exists() for path in (
            self.metadata_path, self.ca_cert_path,
            self.node_cert_path, self.node_key_path,
        ))
        master = common and self.ca_key_path.exists()
        slave = common and joined_slave_files_exist(self.directory.parent)
        if role == "master":
            return master
        if role == "slave":
            return slave
        if role is not None:
            raise ValueError("invalid cluster identity role")
        return master or slave

    def create_master_identity(
        self, cluster_id: str | None = None, node_id: str | None = None,
    ) -> ClusterIdentity:
        if self.exists("master"):
            return self.load_identity()
        if self.exists("slave"):
            raise SecureStorageUnavailable(
                "joined Slave identity must be removed before becoming Master"
            )
        cluster_id = cluster_id or uuid.uuid4().hex
        node_id = node_id or uuid.uuid4().hex
        self._validate_identifier(cluster_id)
        self._validate_identifier(node_id)
        ca_key = Ed25519PrivateKey.generate()
        node_key = Ed25519PrivateKey.generate()
        ca_certificate = self._build_ca(ca_key, cluster_id)
        node_certificate = self._build_node_certificate(
            node_key, node_id, ca_key, ca_certificate,
        )
        self._write_identity(
            cluster_id, node_id, ca_key, ca_certificate,
            node_key, node_certificate,
        )
        return self.load_identity()

    def issue_node_certificate(
        self, node_id: str, public_key,
    ) -> x509.Certificate:
        self._validate_identifier(node_id)
        ca_password = self._required_secret(CA_PASSWORD_NAME)
        try:
            ca_key = serialization.load_pem_private_key(
                self.ca_key_path.read_bytes(), password=ca_password,
            )
        except (OSError, ValueError, TypeError) as error:
            raise SecureStorageUnavailable("cluster CA private key is unavailable") from error
        ca_certificate = _load_certificate(self.ca_cert_path)
        return self._build_node_certificate(
            public_key, node_id, ca_key, ca_certificate, public_only=True,
        )

    def create_node_key(self):
        password = secrets.token_hex(32).encode("ascii")
        key = Ed25519PrivateKey.generate()
        self.backend.store(NODE_PASSWORD_NAME, password)
        _atomic_write(self.node_key_path, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        ))
        return key.public_key()

    def ensure_node_key(self):
        """Return the local node public key without ever exporting its private key."""
        if not self.node_key_path.exists():
            return self.create_node_key()
        return self.load_node_private_key().public_key()

    def load_node_private_key(self):
        """Load the encrypted node key for TLS context construction."""
        password = self._required_secret(NODE_PASSWORD_NAME)
        try:
            return serialization.load_pem_private_key(
                self.node_key_path.read_bytes(), password=password,
            )
        except (OSError, ValueError, TypeError) as error:
            raise SecureStorageUnavailable("cluster node private key is unavailable") from error

    def node_private_key_password(self) -> bytes:
        return self._required_secret(NODE_PASSWORD_NAME)

    def install_joined_identity(
        self, *, cluster_id: str, node_id: str,
        ca_certificate: x509.Certificate, node_certificate: x509.Certificate,
    ) -> ClusterIdentity:
        self._validate_identifier(cluster_id)
        self._validate_identifier(node_id)
        password = self._required_secret(NODE_PASSWORD_NAME)
        try:
            node_private_key = serialization.load_pem_private_key(
                self.node_key_path.read_bytes(), password=password,
            )
            ca_certificate.public_key().verify(
                ca_certificate.signature, ca_certificate.tbs_certificate_bytes,
            )
            ca_certificate.public_key().verify(
                node_certificate.signature, node_certificate.tbs_certificate_bytes,
            )
            basic = ca_certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            san = node_certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.UniformResourceIdentifier)
            expected_uri = f"urn:netshare:node:{node_id}"
            local_public = node_private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            certified_public = node_certificate.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            now = self.now()
            if (
                not basic.ca
                or ca_certificate.subject != ca_certificate.issuer
                or node_certificate.issuer != ca_certificate.subject
                or san != [expected_uri]
                or local_public != certified_public
                or now < node_certificate.not_valid_before_utc
                or now > node_certificate.not_valid_after_utc
            ):
                raise ValueError("certificate identity mismatch")
        except (OSError, ValueError, TypeError, x509.ExtensionNotFound) as error:
            raise SecureStorageUnavailable("joined cluster identity is invalid") from error
        _atomic_write(
            self.ca_cert_path,
            ca_certificate.public_bytes(serialization.Encoding.PEM),
        )
        _atomic_write(
            self.node_cert_path,
            node_certificate.public_bytes(serialization.Encoding.PEM),
        )
        _atomic_write(self.metadata_path, json.dumps({
            "cluster_id": cluster_id, "node_id": node_id,
            "ca_fingerprint": certificate_fingerprint(ca_certificate),
        }, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        return self.load_identity()

    def load_identity(self) -> ClusterIdentity:
        try:
            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            cluster_id = str(metadata["cluster_id"])
            node_id = str(metadata["node_id"])
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise SecureStorageUnavailable("cluster identity metadata is invalid") from error
        certificate = _load_certificate(self.ca_cert_path)
        return ClusterIdentity(
            cluster_id=cluster_id,
            node_id=node_id,
            ca_certificate_path=self.ca_cert_path,
            node_certificate_path=self.node_cert_path,
            node_private_key_path=self.node_key_path,
            node_private_key_password=self._required_secret(NODE_PASSWORD_NAME),
            ca_fingerprint=certificate_fingerprint(certificate),
        )

    def node_certificate_needs_renewal(self) -> bool:
        certificate = _load_certificate(self.node_cert_path)
        threshold = self.now() + timedelta(days=NODE_RENEW_BEFORE_DAYS)
        return certificate.not_valid_after_utc <= threshold

    def renew_master_certificate(self) -> ClusterIdentity:
        identity = self.load_identity()
        node_password = self._required_secret(NODE_PASSWORD_NAME)
        try:
            node_key = serialization.load_pem_private_key(
                self.node_key_path.read_bytes(), password=node_password,
            )
        except (OSError, ValueError, TypeError) as error:
            raise SecureStorageUnavailable("cluster node private key is unavailable") from error
        certificate = self.issue_node_certificate(identity.node_id, node_key.public_key())
        _atomic_write(self.node_cert_path, certificate.public_bytes(serialization.Encoding.PEM))
        return self.load_identity()


    def export_ca_private_key(self) -> bytes:
        """Export the cluster CA key as DER for authenticated failover replication."""
        ca_password = self._required_secret(CA_PASSWORD_NAME)
        try:
            ca_key = serialization.load_pem_private_key(
                self.ca_key_path.read_bytes(), password=ca_password,
            )
        except (OSError, ValueError, TypeError) as error:
            raise SecureStorageUnavailable("cluster CA private key is unavailable") from error
        return ca_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def install_promoted_ca(self, raw_private_key: bytes) -> ClusterIdentity:
        """Turn an existing joined node identity into a Master without changing CA/cert."""
        if not self.exists("slave") and not self.exists():
            raise SecureStorageUnavailable("joined cluster identity is unavailable")
        try:
            ca_key = serialization.load_der_private_key(bytes(raw_private_key), password=None)
            ca_certificate = _load_certificate(self.ca_cert_path)
            expected = ca_certificate.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            actual = ca_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            if expected != actual:
                raise ValueError("cluster CA key mismatch")
        except (OSError, ValueError, TypeError) as error:
            raise SecureStorageUnavailable("failover CA private key is invalid") from error
        password = secrets.token_hex(32).encode("ascii")
        self.backend.store(CA_PASSWORD_NAME, password)
        _atomic_write(self.ca_key_path, ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        ))
        return self.load_identity()

    def demote_master_identity(self) -> ClusterIdentity:
        """Keep the node certificate/key but remove local CA signing capability."""
        if not self.exists("master"):
            return self.load_identity()
        self.ca_key_path.unlink(missing_ok=True)
        self.backend.delete(CA_PASSWORD_NAME)
        return self.load_identity()

    def recover_compromised_ca(self) -> ClusterIdentity:
        previous_node_id = None
        if self.metadata_path.exists():
            try:
                previous_node_id = json.loads(
                    self.metadata_path.read_text(encoding="utf-8")
                ).get("node_id")
            except (OSError, ValueError, TypeError):
                previous_node_id = None
        for path in (
            self.metadata_path, self.ca_cert_path, self.ca_key_path,
            self.node_cert_path, self.node_key_path,
            self.directory / "trusted_peers.json",
        ):
            path.unlink(missing_ok=True)
        self.backend.delete(CA_PASSWORD_NAME)
        self.backend.delete(NODE_PASSWORD_NAME)
        return self.create_master_identity(node_id=previous_node_id)

    def delete_joined_identity(self) -> None:
        """Delete a Slave identity and verify protected envelope keys are absent.

        DPAPI/Keychain deletion removes the recoverable envelope secrets; SSD
        flash remanence cannot be promised or verified bit-for-bit.
        """
        for path in (
            self.metadata_path, self.ca_cert_path, self.ca_key_path,
            self.node_cert_path, self.node_key_path,
            self.directory / "trusted_peers.json",
            self.directory / "master_signing_key.bin",
            self.directory / "master_connection.json",
            self.directory / "bootstrap_cert.pem",
            self.directory / "revocations.json",
        ):
            path.unlink(missing_ok=True)
        self.backend.delete(CA_PASSWORD_NAME)
        self.backend.delete(NODE_PASSWORD_NAME)
        if self.backend.load(CA_PASSWORD_NAME) is not None:
            raise SecureStorageUnavailable("cluster CA secret deletion was not confirmed")
        if self.backend.load(NODE_PASSWORD_NAME) is not None:
            raise SecureStorageUnavailable("cluster node secret deletion was not confirmed")

    def _required_secret(self, name: str) -> bytes:
        secret = self.backend.load(name)
        if secret is None or len(secret) != 64:
            raise SecureStorageUnavailable("cluster key password is unavailable")
        return secret

    @staticmethod
    def _validate_identifier(value: str) -> None:
        if not IDENTIFIER_PATTERN.fullmatch(str(value)):
            raise ValueError("invalid cluster identity")

    def _write_identity(
        self, cluster_id, node_id, ca_key, ca_certificate,
        node_key, node_certificate,
    ) -> None:
        # Hex keeps the full 256-bit entropy while remaining safe for every
        # OpenSSL password callback (including implementations treating NUL
        # as a terminator).
        ca_password = secrets.token_hex(32).encode("ascii")
        node_password = secrets.token_hex(32).encode("ascii")
        self.backend.store(CA_PASSWORD_NAME, ca_password)
        self.backend.store(NODE_PASSWORD_NAME, node_password)
        _atomic_write(self.ca_key_path, ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(ca_password),
        ))
        _atomic_write(self.node_key_path, node_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(node_password),
        ))
        _atomic_write(
            self.ca_cert_path,
            ca_certificate.public_bytes(serialization.Encoding.PEM),
        )
        _atomic_write(
            self.node_cert_path,
            node_certificate.public_bytes(serialization.Encoding.PEM),
        )
        _atomic_write(self.metadata_path, json.dumps({
            "cluster_id": cluster_id,
            "node_id": node_id,
            "ca_fingerprint": certificate_fingerprint(ca_certificate),
        }, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    def _build_ca(self, private_key, cluster_id: str) -> x509.Certificate:
        now = self.now()
        name = x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, f"NetShare Cluster {cluster_id}",
        )])
        return (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=CA_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(private_key, algorithm=None)
        )

    def _build_node_certificate(
        self, key_or_public, node_id, ca_key, ca_certificate, public_only=False,
    ) -> x509.Certificate:
        now = self.now()
        public_key = key_or_public if public_only else key_or_public.public_key()
        subject = x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, f"NetShare Node {node_id}",
        )])
        return (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(ca_certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=NODE_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(f"urn:netshare:node:{node_id}"),
            ]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]), critical=False)
            .sign(ca_key, algorithm=None)
        )
