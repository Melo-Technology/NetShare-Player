"""Authenticated cluster failover state and secure authority replication.

mDNS is only a hint used to discover candidates.  Promotion requires a locally
stored authority replica that was delivered over authenticated cluster mTLS,
and election is restricted to the last authenticated roster.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from dataclasses import asdict
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .identity import ClusterIdentityStore, certificate_fingerprint
from .key_store import KEY_NAME, ClusterKeyStore, SecureKeyBackend
from .registry import ClusterRegistry, MAX_SLAVES, SlaveNode
from .revocation import RevocationRegistry

MAX_MEMBERS = MAX_SLAVES + 1
from .tls import PeerTrustStore

FAILOVER_CA_KEY_NAME = "cluster-failover-ca-pkcs8-v1"
FAILOVER_SIGNING_KEY_NAME = "cluster-failover-signing-ed25519-v1"
FAILOVER_SCHEMA_VERSION = 1
FAILOVER_ELECTION_GRACE_SECONDS = 12.0
TWO_NODE_WITNESSLESS_AFTER_SECONDS = 40.0


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _node_from_dict(value: dict) -> SlaveNode:
    return SlaveNode(
        node_id=str(value["node_id"]), name=str(value["name"]),
        host=str(value["host"]), port=int(value["port"]),
        certificate_serial=int(value["certificate_serial"]),
        online=False, created_at=max(0, int(value.get("created_at", 0) or 0)),
    )


class FailoverAuthorityStore:
    """Secure replica of the minimum authority required to promote a Slave."""

    def __init__(self, config_dir: Path, backend: SecureKeyBackend):
        self.directory = Path(config_dir) / "cluster"
        self.path = self.directory / "failover_replica.json"
        self.backend = backend
        self._lock = threading.RLock()
        self._metadata = self._load()

    @property
    def ready(self) -> bool:
        with self._lock:
            return bool(
                self._metadata.get("authority_version")
                and self.backend.load(FAILOVER_CA_KEY_NAME)
                and self.backend.load(FAILOVER_SIGNING_KEY_NAME)
            )

    @property
    def authority_version(self) -> str:
        with self._lock:
            return str(self._metadata.get("authority_version") or "")

    @property
    def leader_node_id(self) -> str:
        with self._lock:
            return str(self._metadata.get("leader_node_id") or "")

    @property
    def leader_epoch(self) -> int:
        with self._lock:
            return max(0, int(self._metadata.get("leader_epoch", 0) or 0))

    @property
    def roster(self) -> tuple[SlaveNode, ...]:
        with self._lock:
            values = self._metadata.get("roster", [])
            result = []
            for item in values if isinstance(values, list) else []:
                try:
                    result.append(_node_from_dict(item))
                except (KeyError, TypeError, ValueError):
                    continue
            return tuple(result[:MAX_MEMBERS])

    @property
    def ticket_generations(self) -> dict[str, int]:
        """Authenticated per-member ticket generations retained for failover."""
        with self._lock:
            raw = self._metadata.get("ticket_generations", {})
            if not isinstance(raw, dict):
                return {}
            result: dict[str, int] = {}
            for raw_node_id, raw_generation in list(raw.items())[:MAX_MEMBERS]:
                node_id = str(raw_node_id)[:128]
                if not node_id:
                    continue
                try:
                    result[node_id] = max(0, int(raw_generation))
                except (TypeError, ValueError):
                    continue
            return result

    def install_authority(
        self, *, identity_store: ClusterIdentityStore, ca_private_key: bytes,
        signing_private_key: bytes, authority_version: str,
        leader_node_id: str, leader_epoch: int, roster: list[dict],
        ticket_generations: dict[str, int] | None = None,
    ) -> None:
        """Install authority bytes received only through authenticated mTLS."""
        if len(signing_private_key) != 32:
            raise ValueError("invalid failover signing key")
        ca_key = serialization.load_der_private_key(ca_private_key, password=None)
        ca_cert = x509.load_pem_x509_certificate(identity_store.ca_cert_path.read_bytes())
        local_public = ca_cert.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        received_public = ca_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        if local_public != received_public:
            raise ValueError("failover CA does not match joined cluster")
        derived_public = Ed25519PrivateKey.from_private_bytes(signing_private_key).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        public_path = self.directory / "master_signing_key.bin"
        if public_path.exists() and public_path.read_bytes() != derived_public:
            raise ValueError("failover signing key does not match joined cluster")
        self.backend.store(FAILOVER_CA_KEY_NAME, bytes(ca_private_key))
        self.backend.store(FAILOVER_SIGNING_KEY_NAME, bytes(signing_private_key))
        self.update_metadata(
            authority_version=authority_version, leader_node_id=leader_node_id,
            leader_epoch=leader_epoch, roster=roster,
            ticket_generations=ticket_generations,
        )

    def update_metadata(
        self, *, authority_version: str | None = None,
        leader_node_id: str | None = None, leader_epoch: int | None = None,
        roster: list[dict] | None = None,
        ticket_generations: dict[str, int] | None = None,
    ) -> None:
        with self._lock:
            value = dict(self._metadata)
            value["v"] = FAILOVER_SCHEMA_VERSION
            if authority_version is not None:
                value["authority_version"] = str(authority_version)[:128]
            if leader_node_id is not None:
                value["leader_node_id"] = str(leader_node_id)[:128]
            if leader_epoch is not None:
                value["leader_epoch"] = max(0, int(leader_epoch))
            if roster is not None:
                clean = []
                seen = set()
                for item in roster[:MAX_MEMBERS]:
                    node = _node_from_dict(item)
                    if not node.node_id or node.node_id in seen:
                        continue
                    seen.add(node.node_id)
                    clean.append(asdict(node))
                value["roster"] = clean
            if ticket_generations is not None:
                if not isinstance(ticket_generations, dict):
                    raise ValueError("ticket generations must be a mapping")
                existing = self.ticket_generations
                allowed = None
                roster_value = value.get("roster")
                if isinstance(roster_value, list) and roster_value:
                    allowed = {str(item.get("node_id") or "") for item in roster_value}
                    allowed.discard("")
                merged: dict[str, int] = {}
                for raw_node_id, raw_generation in ticket_generations.items():
                    node_id = str(raw_node_id)[:128]
                    if not node_id or (allowed is not None and node_id not in allowed):
                        continue
                    try:
                        generation = max(0, int(raw_generation))
                    except (TypeError, ValueError) as error:
                        raise ValueError("invalid ticket generation") from error
                    merged[node_id] = max(existing.get(node_id, 0), generation)
                if allowed is not None:
                    for node_id in allowed:
                        if node_id in existing and node_id not in merged:
                            merged[node_id] = existing[node_id]
                value["ticket_generations"] = dict(list(merged.items())[:MAX_MEMBERS])
            self._metadata = value
            _atomic_json(self.path, value)

    def ensure_master_backup(
        self, *, identity_store: ClusterIdentityStore,
        signing_private_key: bytes, leader_node_id: str, leader_epoch: int,
        roster: list[dict], ticket_generations: dict[str, int] | None = None,
    ) -> str:
        ca_raw = identity_store.export_ca_private_key()
        ca_fp = certificate_fingerprint(
            x509.load_pem_x509_certificate(identity_store.ca_cert_path.read_bytes())
        )
        signing_public = Ed25519PrivateKey.from_private_bytes(signing_private_key).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        version = hashlib.sha256(
            (ca_fp + ":").encode("ascii") + signing_public
        ).hexdigest()[:32]
        self.backend.store(FAILOVER_CA_KEY_NAME, ca_raw)
        self.backend.store(FAILOVER_SIGNING_KEY_NAME, bytes(signing_private_key))
        self.update_metadata(
            authority_version=version, leader_node_id=leader_node_id,
            leader_epoch=leader_epoch, roster=roster,
            ticket_generations=ticket_generations,
        )
        return version

    def export_transport_bundle(self) -> dict:
        with self._lock:
            ca = self.backend.load(FAILOVER_CA_KEY_NAME)
            signing = self.backend.load(FAILOVER_SIGNING_KEY_NAME)
            if not ca or not signing or not self.authority_version:
                return {}
            return {
                "v": FAILOVER_SCHEMA_VERSION,
                "authority_version": self.authority_version,
                "ca_private_key": base64.b64encode(ca).decode("ascii"),
                "signing_private_key": base64.b64encode(signing).decode("ascii"),
            }

    def import_transport_bundle(
        self, bundle: dict, *, identity_store: ClusterIdentityStore,
        leader_node_id: str, leader_epoch: int, roster: list[dict],
        ticket_generations: dict[str, int] | None = None,
    ) -> None:
        if not isinstance(bundle, dict) or int(bundle.get("v", 0)) != FAILOVER_SCHEMA_VERSION:
            raise ValueError("invalid failover authority bundle")
        try:
            ca = base64.b64decode(str(bundle["ca_private_key"]), validate=True)
            signing = base64.b64decode(str(bundle["signing_private_key"]), validate=True)
        except Exception as error:
            raise ValueError("invalid failover authority encoding") from error
        self.install_authority(
            identity_store=identity_store, ca_private_key=ca,
            signing_private_key=signing,
            authority_version=str(bundle.get("authority_version") or ""),
            leader_node_id=leader_node_id, leader_epoch=leader_epoch,
            roster=roster, ticket_generations=ticket_generations,
        )

    def promote_local(
        self, *, identity_store: ClusterIdentityStore,
        key_store: ClusterKeyStore, local_node_id: str,
        new_epoch: int,
    ) -> tuple[SlaveNode, ...]:
        with self._lock:
            ca = self.backend.load(FAILOVER_CA_KEY_NAME)
            signing = self.backend.load(FAILOVER_SIGNING_KEY_NAME)
            if not ca or not signing:
                raise RuntimeError("failover authority is unavailable")
            identity_store.install_promoted_ca(ca)
            key_store.backend.store(KEY_NAME, signing)
            survivors = tuple(
                node for node in self.roster if node.node_id != local_node_id
            )
            if len(survivors) > MAX_SLAVES:
                raise RuntimeError("failover membership exceeds Slave capacity")
            registry = ClusterRegistry(self.directory / "nodes.json")
            for existing in tuple(registry.nodes):
                registry.remove(existing.node_id)
            for node in survivors:
                registry.add(node)
            # The promoted node must inherit the last authenticated generation
            # for every audience before its MasterRelay can sign any ticket.
            # Local persisted state still wins if it is newer.
            RevocationRegistry(self.directory / "revocations.json").merge_generations(
                self.ticket_generations
            )
            self.update_metadata(
                leader_node_id=local_node_id, leader_epoch=new_epoch,
                roster=[asdict(node) for node in self.roster],
                ticket_generations=self.ticket_generations,
            )
            return survivors

    def prepare_demoted_master(
        self, *, identity_store: ClusterIdentityStore,
        key_store: ClusterKeyStore, new_leader_node_id: str,
        new_epoch: int,
    ) -> None:
        """Retain node identity but remove active Master authority from runtime use."""
        signing = key_store.backend.load(KEY_NAME)
        if signing:
            self.backend.store(FAILOVER_SIGNING_KEY_NAME, signing)
            public = Ed25519PrivateKey.from_private_bytes(signing).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            (self.directory / "master_signing_key.bin").write_bytes(public)
        ca_raw = identity_store.export_ca_private_key()
        self.backend.store(FAILOVER_CA_KEY_NAME, ca_raw)
        identity_store.demote_master_identity()
        key_store.delete_private_key()
        (self.directory / "nodes.json").unlink(missing_ok=True)
        self.update_metadata(
            leader_node_id=new_leader_node_id, leader_epoch=new_epoch,
        )

    def sync_trust_store(self, trust: PeerTrustStore, *, local_node_id: str) -> None:
        if not self.roster:
            return
        desired = {
            node.node_id: node.certificate_serial for node in self.roster
            if node.node_id != local_node_id
        }
        for node_id in tuple(trust.node_ids):
            if node_id not in desired:
                trust.revoke(node_id)
        for node_id, serial in desired.items():
            trust.allow_serial(node_id, serial)

    def clear(self) -> None:
        with self._lock:
            self.backend.delete(FAILOVER_CA_KEY_NAME)
            self.backend.delete(FAILOVER_SIGNING_KEY_NAME)
            self._metadata = {}
            self.path.unlink(missing_ok=True)

    def _load(self) -> dict:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}


def election_rank(created_at: int | float, node_id: str) -> tuple[int, str]:
    born = int(float(created_at or 0))
    return (born if born > 0 else 2**62, str(node_id))


def quorum_required(member_count: int) -> int:
    """Strict majority of the last authenticated cluster membership."""
    total = max(1, int(member_count))
    return total // 2 + 1
