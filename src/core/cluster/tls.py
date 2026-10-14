"""TLS 1.3 mutual-authentication helpers for the inter-node channel."""

from __future__ import annotations

import json
import os
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from .identity import ClusterIdentity

MAX_TRUSTED_PEERS = 6
ALPN_PROTOCOL = "netshare-cluster/1"


class PeerAuthorizationError(PermissionError):
    pass


class PeerCertificateSerialMismatch(PeerAuthorizationError):
    def __init__(self, node_id: str, expected: int, actual: int):
        self.node_id = node_id
        self.expected = int(expected)
        self.actual = int(actual)
        super().__init__(
            f"peer certificate serial mismatch for {node_id}: "
            f"expected {expected}, got {actual}"
        )


@dataclass(frozen=True)
class TrustedPeer:
    node_id: str
    certificate_serial: int


class PeerTrustStore:
    def __init__(self, path: Path, ca_fingerprint: str):
        self.path = path
        self.ca_fingerprint = ca_fingerprint
        self._lock = threading.RLock()
        self._peers: dict[str, TrustedPeer] = {}
        self._load()

    def allow(self, node_id: str, certificate: x509.Certificate) -> None:
        if not node_id or len(node_id) > 128:
            raise ValueError("invalid node identity")
        with self._lock:
            if node_id not in self._peers and len(self._peers) >= MAX_TRUSTED_PEERS:
                raise ValueError("cluster peer limit reached")
            self._peers[node_id] = TrustedPeer(node_id, certificate.serial_number)
            self._save()


    def allow_serial(self, node_id: str, certificate_serial: int) -> None:
        """Authorize a peer serial learned from the authenticated Master roster."""
        if not node_id or len(node_id) > 128 or int(certificate_serial) <= 0:
            raise ValueError("invalid node identity")
        with self._lock:
            if node_id not in self._peers and len(self._peers) >= MAX_TRUSTED_PEERS:
                raise ValueError("cluster peer limit reached")
            self._peers[node_id] = TrustedPeer(str(node_id), int(certificate_serial))
            self._save()

    def revoke(self, node_id: str) -> None:
        with self._lock:
            self._peers.pop(node_id, None)
            self._save()

    @property
    def node_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._peers))

    def authorize_der(self, certificate_der: bytes) -> TrustedPeer:
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
            uris = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value.get_values_for_type(x509.UniformResourceIdentifier)
        except (ValueError, x509.ExtensionNotFound) as error:
            raise PeerAuthorizationError("peer certificate identity is invalid") from error
        prefix = "urn:netshare:node:"
        node_ids = [value[len(prefix):] for value in uris if value.startswith(prefix)]
        if len(node_ids) != 1:
            raise PeerAuthorizationError("peer certificate identity is invalid")
        with self._lock:
            peer = self._peers.get(node_ids[0])
            if peer is None:
                raise PeerAuthorizationError("peer certificate is not authorized")
            if peer.certificate_serial != certificate.serial_number:
                raise PeerCertificateSerialMismatch(
                    peer.node_id, peer.certificate_serial, certificate.serial_number,
                )
            return peer

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if value.get("ca_fingerprint") != self.ca_fingerprint:
                raise ValueError("cluster CA changed")
            peers = value.get("peers", [])
            if not isinstance(peers, list) or len(peers) > MAX_TRUSTED_PEERS:
                raise ValueError("invalid peer registry")
            for item in peers:
                peer = TrustedPeer(str(item["node_id"]), int(item["serial"]))
                self._peers[peer.node_id] = peer
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise PeerAuthorizationError("trusted peer registry is invalid") from error

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({
            "ca_fingerprint": self.ca_fingerprint,
            "peers": [
                {"node_id": peer.node_id, "serial": peer.certificate_serial}
                for peer in sorted(self._peers.values(), key=lambda value: value.node_id)
            ],
        }, separators=(",", ":"), sort_keys=True), encoding="utf-8")
        os.replace(temporary, self.path)


def _configure_context(context: ssl.SSLContext, identity: ClusterIdentity) -> None:
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_NO_COMPRESSION
    context.set_alpn_protocols([ALPN_PROTOCOL])
    context.load_verify_locations(cafile=str(identity.ca_certificate_path))
    context.load_cert_chain(
        certfile=str(identity.node_certificate_path),
        keyfile=str(identity.node_private_key_path),
        password=identity.node_private_key_password,
    )


def server_context(identity: ClusterIdentity) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _configure_context(context, identity)
    return context


def client_context(identity: ClusterIdentity) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    _configure_context(context, identity)
    return context


def connect_mutual_tls(
    address: tuple[str, int], identity: ClusterIdentity,
    trust_store: PeerTrustStore, timeout: float = 5.0,
    log=lambda _message, _kind="info": None,
) -> tuple[ssl.SSLSocket, TrustedPeer]:
    log(f"CLUSTER mTLS TCP connect -> {address[0]}:{address[1]}", "info")
    raw = socket.create_connection(address, timeout=timeout)
    log(f"CLUSTER mTLS TCP connected -> {address[0]}:{address[1]}", "info")
    secure = None
    try:
        log(f"CLUSTER mTLS handshake start -> {address[0]}:{address[1]}", "info")
        secure = client_context(identity).wrap_socket(raw, server_hostname=None)
        if secure.selected_alpn_protocol() != ALPN_PROTOCOL:
            raise PeerAuthorizationError("cluster TLS protocol was not negotiated")
        peer = trust_store.authorize_der(secure.getpeercert(binary_form=True))
        log(
            f"CLUSTER mTLS handshake success -> {address[0]}:{address[1]} "
            f"[peer={peer.node_id}]",
            "ok",
        )
        return secure, peer
    except Exception as error:
        log(
            f"CLUSTER mTLS handshake failed -> {address[0]}:{address[1]}: "
            f"{type(error).__name__}: {error}",
            "error",
        )
        (secure or raw).close()
        raise


def accept_mutual_tls(
    listener: socket.socket, identity: ClusterIdentity,
    trust_store: PeerTrustStore, log=lambda _message, _kind="info": None,
) -> tuple[ssl.SSLSocket, TrustedPeer]:
    raw, address = listener.accept()
    remote = f"{address[0]}:{address[1]}"
    log(f"CLUSTER Slave TCP accepted <- {remote}", "info")
    secure = None
    try:
        log(f"CLUSTER Slave mTLS handshake start <- {remote}", "info")
        secure = server_context(identity).wrap_socket(raw, server_side=True)
        if secure.selected_alpn_protocol() != ALPN_PROTOCOL:
            raise PeerAuthorizationError("cluster TLS protocol was not negotiated")
        peer = trust_store.authorize_der(secure.getpeercert(binary_form=True))
        log(
            f"CLUSTER Slave mTLS handshake success <- {remote} "
            f"[peer={peer.node_id}]",
            "ok",
        )
        return secure, peer
    except Exception as error:
        log(
            f"CLUSTER Slave mTLS handshake failed <- {remote}: "
            f"{type(error).__name__}: {error}",
            "error",
        )
        (secure or raw).close()
        raise
