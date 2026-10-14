"""Lifecycle wiring for discovery, bootstrap, mTLS and exact-range relay."""

from __future__ import annotations

import socket
import threading
import time
import uuid
import secrets
from pathlib import Path
from dataclasses import asdict

from src.core import unlock_codes
from src.core.derived_media import derived_media_service
import src.deps as deps
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .bootstrap import (
    BootstrapTarget,
)
from .audit import ClusterAuditLog
from .sas_bootstrap import SlaveSasSession, enroll_sas
from .sas_pairing import Ceremony
from .control import ClusterControlService
from .discovery import (
    DiscoveredNode, DiscoveryAdvertiser, DiscoveryBrowser,
    choose_auto_role, scan_for_auto_election,
)
from .fallback import SlaveFallbackState
from .failover import (
    FAILOVER_ELECTION_GRACE_SECONDS, TWO_NODE_WITNESSLESS_AFTER_SECONDS,
    FailoverAuthorityStore, election_rank, quorum_required,
)
from .leadership import LeaderProbeListener, probe_leader
from .identity import ClusterIdentityStore
from .key_store import ClusterKeyStore, SecureKeyBackend, default_backend
from .listing import ListingCursorCodec
from .protocol import (
    SlaveFileProtocol, receive_frame, send_frame,
    request_relay_replica_write, request_relay_replica_delete,
    request_relay_replica_prune,
)
from .registry import ClusterRegistry, MAX_SLAVES
from .relay import MasterRelay
from .revocation import RevocationRegistry
from .tickets import TicketIssuer, TicketValidationError, TicketVerifier
from .tls import (
    PeerAuthorizationError, PeerCertificateSerialMismatch, PeerTrustStore,
    accept_mutual_tls, connect_mutual_tls,
)


HEARTBEAT_INTERVAL_SECONDS = 10.0
HEARTBEAT_FAILURE_THRESHOLD = 3
HEARTBEAT_BACKOFF_SECONDS = (15.0, 30.0, 60.0)


def _noop_node_change(_node_id: str, _name: str, _online: bool) -> None:
    return None


def _noop_fallback_change(_enabled: bool, _metadata: dict) -> None:
    return None


def _noop_superseded(_node_id: str, _epoch: int) -> None:
    return None


def _safe_callback(value, fallback):
    """Normalize optional callbacks at the runtime boundary.

    ``ServerRuntimeController.start`` intentionally accepts ``None`` for GUI
    callbacks.  Cluster worker threads must never call that sentinel directly;
    a missing UI observer is a valid headless configuration, not a fatal error.
    """
    return value if callable(value) else fallback


def _local_media_capabilities() -> dict[str, bool]:
    """Return non-sensitive media capabilities for authenticated heartbeats."""
    return {
        "known": True,
        "ffmpeg": bool(deps.HAS_FFMPEG),
        "audio_analysis": bool(deps.HAS_AUDIO_ANALYSIS),
        "video_thumbnails": bool(deps.HAS_VIDEO_THUMBNAILS),
        "hls_transcoding": bool(deps.HAS_HLS_TRANSCODING),
    }


def _normalize_media_capabilities(value) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {"known": False}
    allowed = ("ffmpeg", "audio_analysis", "video_thumbnails", "hls_transcoding")
    if not any(key in value for key in allowed):
        return {"known": False}
    return {"known": True, **{key: value.get(key) is True for key in allowed}}


class ClusterFileListener:
    def __init__(
        self, *, host: str, port: int, identity, trust_store: PeerTrustStore,
        protocol: SlaveFileProtocol, log=lambda _message, _kind="info": None,
    ):
        self.host = host
        self.port = int(port)
        self.identity = identity
        self.trust_store = trust_store
        self.protocol = protocol
        self._log = log
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    @property
    def bound_port(self) -> int:
        if self._listener is None:
            return self.port
        return int(self._listener.getsockname()[1])

    def start(self) -> int:
        if self._listener is not None:
            raise RuntimeError("cluster file listener is already active")
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(8)
        listener.settimeout(0.5)
        self._listener = listener
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="netshare-cluster-file",
        )
        self._thread.start()
        return self.bound_port

    def _serve(self) -> None:
        while not self._stopping.is_set():
            try:
                secure, peer = accept_mutual_tls(
                    self._listener, self.identity, self.trust_store,
                    log=self._log,
                )
            except (OSError, TimeoutError) as error:
                if not isinstance(error, (socket.timeout, TimeoutError)):
                    self._log(
                        f"CLUSTER Slave listener rejected connection: "
                        f"{type(error).__name__}: {error}",
                        "error",
                    )
                continue
            thread = threading.Thread(
                target=self._handle, args=(secure, peer.node_id), daemon=True,
                name="netshare-cluster-request",
            )
            thread.start()

    def _handle(self, secure, peer_id: str) -> None:
        try:
            secure.settimeout(5.0)
            self._log(
                f"CLUSTER Slave request accepted from {peer_id}", "info",
            )
            self.protocol.handle_once(secure, peer_id)
            self._log(
                f"CLUSTER Slave request completed for {peer_id}", "ok",
            )
        except TicketValidationError as error:
            try:
                send_frame(secure, {
                    "status": 403,
                    "error": error.code.value,
                    "message": f"cluster ticket rejected: {error.code.value}",
                })
            except (ConnectionError, OSError, ValueError):
                pass
            self._log(
                f"CLUSTER Slave request rejected for {peer_id}: "
                f"TicketValidationError: {error.code.value}",
                "error",
            )
        except (ConnectionError, OSError, ValueError) as error:
            self._log(
                f"CLUSTER Slave request failed for {peer_id}: "
                f"{type(error).__name__}: {error}",
                "error",
            )
        finally:
            secure.close()

    def stop(self) -> None:
        self._stopping.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)


class MasterClusterRuntime:
    def __init__(
        self, *, config_dir: Path, root: Path, backend: SecureKeyBackend,
        node_id: str, node_name: str, master_lan_url: str = "",
        addresses: list[str] | None = None, discovery_port: int = 0,
        node_created_at: int | float = 0,
        heartbeat_failure_threshold: int = HEARTBEAT_FAILURE_THRESHOLD,
        heartbeat_backoff_seconds: tuple[float, ...] = HEARTBEAT_BACKOFF_SECONDS,
        on_node_change=lambda _node_id, _name, _online: None,
        on_superseded=lambda _node_id, _epoch: None,
        log=lambda _message, _kind="info": None,
    ):
        self.config_dir = config_dir / "cluster"
        self.root = root
        self.node_id = node_id
        self.node_name = node_name
        self.master_lan_url = master_lan_url
        self.addresses = list(addresses or [])
        self.discovery_port = int(discovery_port or 0)
        self.node_created_at = int(float(node_created_at or 0))
        self._on_node_change = _safe_callback(on_node_change, _noop_node_change)
        self._on_superseded = _safe_callback(on_superseded, _noop_superseded)
        self._log = log
        self.identity_store = ClusterIdentityStore(config_dir, backend)
        self.identity = self.identity_store.create_master_identity(node_id=node_id)
        self.trust = PeerTrustStore(
            self.config_dir / "trusted_peers.json", self.identity.ca_fingerprint,
        )
        self.registry = ClusterRegistry(self.config_dir / "nodes.json")
        self.audit_log = ClusterAuditLog(self.config_dir / "audit.jsonl")
        self.revocations = RevocationRegistry(self.config_dir / "revocations.json")
        self.key_store = ClusterKeyStore(backend)
        private_key = self.key_store.get_or_create_private_key()
        self._signing_private_key = private_key
        signing_public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self._signing_public_key = signing_public_key
        self.failover_authority = FailoverAuthorityStore(config_dir, backend)
        prior_epoch = self.failover_authority.leader_epoch
        prior_leader = self.failover_authority.leader_node_id
        self.leader_epoch = max(1, prior_epoch if prior_leader == self.node_id else 1)
        self.failover_authority.ensure_master_backup(
            identity_store=self.identity_store, signing_private_key=private_key,
            leader_node_id=self.node_id, leader_epoch=self.leader_epoch,
            roster=[],
        )
        self._failover_synced: dict[str, str] = {}
        self._supersede_probe_active = False
        self.leader_listener = None
        self._discovered: dict[tuple[str, str], BootstrapTarget] = {}
        self._discovered_created_at: dict[tuple[str, str], int] = {}
        self._pairing_open: set[tuple[str, str]] = set()
        self._nearby: dict[str, DiscoveredNode] = {}
        self._active_pairing_target: BootstrapTarget | None = None
        self.ceremony = None
        self.pairing_error = ""
        self.last_unpair_status = ""
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread = None
        self._heartbeat_failures: dict[str, int] = {}
        self._heartbeat_next_attempt: dict[str, float] = {}
        self._node_media_capabilities: dict[str, dict[str, bool]] = {}
        # Registered peers start with a fresh grace window on each runtime start.
        self._heartbeat_states: dict[str, str] = {
            node.node_id: "reachable" for node in self.registry.nodes
        }
        self._heartbeat_failure_threshold = max(
            1, int(heartbeat_failure_threshold),
        )
        schedule = tuple(float(delay) for delay in heartbeat_backoff_seconds)
        if not schedule or any(delay <= 0 for delay in schedule):
            raise ValueError("heartbeat backoff must contain positive delays")
        self._heartbeat_backoff_seconds = schedule
        self._clock = time.monotonic
        self.browser = DiscoveryBrowser()
        self.presence_advertiser = DiscoveryAdvertiser(self.addresses)
        self.relay = MasterRelay(
            cluster_id=self.identity.cluster_id,
            master_node_id=self.identity.node_id,
            issuer=TicketIssuer(private_key, log=self._log),
            generation_for=self.revocations.current_generation,
            connect_to=self._connect_to,
            log=self._log,
        )
        self.control = ClusterControlService(
            self.registry, remove_node=self.remove_node,
            node_status=self.node_status,
            audit_log=self.audit_log,
        )
        self.failover_authority.ensure_master_backup(
            identity_store=self.identity_store, signing_private_key=self._signing_private_key,
            leader_node_id=self.node_id, leader_epoch=self.leader_epoch,
            roster=self._failover_roster(),
            ticket_generations=self._ticket_generations_snapshot(),
        )

    def _failover_roster(self) -> list[dict]:
        certificate = x509.load_pem_x509_certificate(
            self.identity.node_certificate_path.read_bytes()
        )
        leader_host = self.addresses[0] if self.addresses else ""
        leader_port = self.discovery_port + 4 if self.discovery_port else 0
        members = [{
            "node_id": self.node_id, "name": self.node_name,
            "host": leader_host, "port": leader_port,
            "certificate_serial": certificate.serial_number,
            "online": True, "created_at": self.node_created_at,
        }]
        members.extend(asdict(node) for node in self.registry.nodes)
        return members

    def _ticket_generations_snapshot(self, roster: list[dict] | None = None) -> dict[str, int]:
        members = roster if roster is not None else self._failover_roster()
        return self.revocations.generation_snapshot(
            str(item.get("node_id") or "") for item in members
            if isinstance(item, dict) and item.get("node_id")
        )

    def start(self) -> None:
        leader_port = self.discovery_port + 4 if self.discovery_port else 0
        if leader_port and self.addresses and leader_port <= 65535:
            self.leader_listener = LeaderProbeListener(
                host="0.0.0.0", port=leader_port, identity=self.identity,
                trust_store=self.trust, node_id=self.node_id,
                epoch_getter=lambda: self.leader_epoch, log=self._log,
            )
            leader_port = self.leader_listener.start()
        if self.discovery_port and self.addresses:
            self.presence_advertiser.start(
                self.discovery_port, role="master", content_port=(leader_port or self.discovery_port),
                node_id=self.node_id, name=self.node_name, pairing_open=False,
                created_at=self.node_created_at, leader_epoch=self.leader_epoch, duration_seconds=None,
            )
        self.browser.start(self._update_discovered)
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True,
            name="netshare-cluster-heartbeat",
        )
        self._heartbeat_thread.start()
        self._log(
            f"CLUSTER heartbeat started ({len(self.registry.nodes)} registered node(s))",
            "info",
        )

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.is_set():
            nodes = self.registry.nodes
            known = {node.node_id for node in nodes}
            for node_id in tuple(self._heartbeat_next_attempt):
                if node_id not in known:
                    self._heartbeat_next_attempt.pop(node_id, None)
                    self._heartbeat_failures.pop(node_id, None)
                    self._heartbeat_states.pop(node_id, None)
            now = self._clock()
            for node in nodes:
                if self._heartbeat_stop.is_set():
                    break
                if now < self._heartbeat_next_attempt.get(node.node_id, 0.0):
                    continue
                try:
                    self._heartbeat(node.node_id)
                except Exception as error:
                    # Heartbeat is a long-lived resilience worker.  Unexpected
                    # observer/provider failures are logged and retried instead
                    # of permanently killing cluster reachability detection.
                    self._log(
                        f"CLUSTER heartbeat iteration failed for {node.node_id}: "
                        f"{type(error).__name__}: {error}",
                        "error",
                    )
                    failures = self._heartbeat_failures.get(node.node_id, 0) + 1
                    self._heartbeat_failures[node.node_id] = failures
                    if failures >= getattr(
                        self, "_heartbeat_failure_threshold", HEARTBEAT_FAILURE_THRESHOLD
                    ):
                        self.registry.set_online(node.node_id, False)
                self._heartbeat_next_attempt[node.node_id] = (
                    self._clock() + self._heartbeat_delay(node.node_id)
                )
            if self._heartbeat_stop.is_set():
                break
            if not nodes:
                delay = HEARTBEAT_INTERVAL_SECONDS
            else:
                next_attempt = min(
                    self._heartbeat_next_attempt.get(node.node_id, self._clock())
                    for node in nodes
                )
                delay = max(
                    0.05, min(
                        HEARTBEAT_INTERVAL_SECONDS, next_attempt - self._clock(),
                    ),
                )
            self._heartbeat_stop.wait(delay)

    def _heartbeat_delay(self, node_id: str) -> float:
        failures = self._heartbeat_failures.get(node_id, 0)
        threshold = getattr(
            self, "_heartbeat_failure_threshold", HEARTBEAT_FAILURE_THRESHOLD,
        )
        if failures < threshold:
            return HEARTBEAT_INTERVAL_SECONDS
        schedule = getattr(
            self, "_heartbeat_backoff_seconds", HEARTBEAT_BACKOFF_SECONDS,
        )
        index = min(failures - threshold, len(schedule) - 1)
        return schedule[index]

    def node_status(self, node_id: str) -> dict:
        node = self.registry.get(node_id)
        failures = self._heartbeat_failures.get(node_id, 0)
        state = self._heartbeat_states.get(node_id)
        if state is None:
            state = "reachable" if node is not None and node.online else "unreachable"
        status = {
            "state": state,
            "consecutive_failures": failures,
        }
        capabilities = getattr(self, "_node_media_capabilities", {})
        if node_id in capabilities:
            status["media_capabilities"] = dict(capabilities[node_id])
        return status

    def _set_heartbeat_state(
        self, node_id: str, label: str, state: str, failures: int,
    ) -> None:
        previous = self._heartbeat_states.get(node_id)
        if previous is None:
            node = self.registry.get(node_id)
            previous = "reachable" if node is not None and node.online else "unreachable"
        self._heartbeat_states[node_id] = state
        if state == previous:
            return
        detail = f", failures={failures}"
        if state == "unreachable":
            detail += f", next_probe={self._heartbeat_delay(node_id):g}s"
        self._log(
            f"CLUSTER node {label} state: {previous} -> {state}{detail}",
            "error" if state == "unreachable" else (
                "ok" if state == "reachable" else "info"
            ),
        )
        if state in ("reachable", "unreachable"):
            self._audit_event(
                state, node_id=node_id, node_name=label,
                consecutive_failures=failures,
            )

    def _audit_event(self, event: str, *, node_id: str = "", **details) -> None:
        audit_log = getattr(self, "audit_log", None)
        if audit_log is not None and not audit_log.record(
            event, node_id=node_id, **details,
        ):
            self._log("CLUSTER audit journal write failed", "error")

    def _heartbeat(self, node_id: str) -> bool:
        nonce = secrets.token_hex(16)
        secure = None
        node = self.registry.get(node_id)
        previous = node.online if node is not None else False
        label = node.name if node is not None else node_id
        try:
            secure = self._connect_to(
                node_id, mark_failure=False, mark_online=False,
            )
            roster = self._failover_roster()
            generations = self._ticket_generations_snapshot(roster)
            self.failover_authority.update_metadata(
                leader_node_id=self.node_id, leader_epoch=self.leader_epoch,
                roster=roster, ticket_generations=generations,
            )
            failover_payload = {
                "authority_version": self.failover_authority.authority_version,
                "leader_node_id": self.node_id, "leader_epoch": self.leader_epoch,
                "roster": roster, "ticket_generations": generations,
            }
            if self._failover_synced.get(node_id) != self.failover_authority.authority_version:
                failover_payload["authority"] = self.failover_authority.export_transport_bundle()
            send_frame(secure, {
                "op": "PING", "nonce": nonce,
                "master_name": self.node_name,
                "master_url": self.master_lan_url,
                "failover": failover_payload,
            })
            response = receive_frame(secure)
            online = response.get("status") == 200 and response.get("nonce") == nonce
            if online and "media_capabilities" in response:
                capabilities = getattr(self, "_node_media_capabilities", None)
                if capabilities is None:
                    capabilities = self._node_media_capabilities = {}
                capabilities[node_id] = _normalize_media_capabilities(
                    response.get("media_capabilities")
                )
            if online and "ticket_generation" in response:
                try:
                    remote_generation = max(0, int(response.get("ticket_generation", 0)))
                except (TypeError, ValueError):
                    remote_generation = -1
                current_generation = self.revocations.current_generation(node_id)
                if remote_generation > current_generation:
                    self.revocations.synchronize_generation(node_id, remote_generation)
                    self.failover_authority.update_metadata(
                        ticket_generations=self._ticket_generations_snapshot(roster),
                    )
                    self._log(
                        f"CLUSTER ticket generation reconciled from authenticated "
                        f"Slave {node_id}: {current_generation} -> {remote_generation}",
                        "info",
                    )
            if online and response.get("failover_version") == self.failover_authority.authority_version:
                self._failover_synced[node_id] = self.failover_authority.authority_version
        except (PeerAuthorizationError, ConnectionError, OSError, ValueError) as error:
            if isinstance(error, PeerCertificateSerialMismatch):
                self._audit_event(
                    "identity_conflict", node_id=node_id,
                    node_name=label, reason=type(error).__name__,
                )
            online = bool(
                node is not None
                and self._heartbeat_failures.get(node_id, 0) >= getattr(
                    self, "_heartbeat_failure_threshold",
                    HEARTBEAT_FAILURE_THRESHOLD,
                )
                and self._recover_discovered(node, nonce)
            )
        finally:
            if secure is not None:
                secure.close()
        if online:
            self._heartbeat_failures[node_id] = 0
            self.registry.set_online(node_id, True)
            self._set_heartbeat_state(node_id, label, "reachable", 0)
        else:
            failures = self._heartbeat_failures.get(node_id, 0) + 1
            self._heartbeat_failures[node_id] = failures
            threshold = getattr(
                self, "_heartbeat_failure_threshold",
                HEARTBEAT_FAILURE_THRESHOLD,
            )
            if failures >= threshold:
                self.registry.set_online(node_id, False)
            self._set_heartbeat_state(
                node_id, label,
                "unreachable" if failures >= threshold else "degraded",
                failures,
            )
        current = self.registry.get(node_id)
        current_online = current.online if current is not None else False
        if current_online != previous:
            self._on_node_change(node_id, label, current_online)
            if current_online:
                # B3: a Slave that was offline receives a complete opaque relay
                # snapshot before it can be relied upon for failover.
                threading.Thread(
                    target=self.sync_p2p_relays_to_node, args=(node_id,), daemon=True,
                    name="netshare-p2p-relay-resync",
                ).start()
        return online

    def _recover_discovered(self, node, nonce: str) -> bool:
        candidates = sorted(
            (target for target in tuple(self._discovered.values())
             if target.node_id == node.node_id),
            key=lambda target: (target.window_id, target.host, target.content_port),
        )
        for target in candidates:
            endpoint = (target.host, target.content_port)
            if endpoint == (node.host, node.port):
                continue
            secure = None
            try:
                secure, peer = connect_mutual_tls(
                    endpoint, self.identity, self.trust, log=self._log,
                )
                if peer.node_id != node.node_id:
                    raise PeerAuthorizationError(
                        "cluster recovery peer identity mismatch"
                    )
                send_frame(secure, {
                    "op": "PING", "nonce": nonce,
                    "master_name": self.node_name,
                    "master_url": self.master_lan_url,
                })
                response = receive_frame(secure)
                if response.get("status") != 200 or response.get("nonce") != nonce:
                    raise ValueError("cluster recovery heartbeat validation failed")
                if not self.registry.update_endpoint(
                    node.node_id, target.host, target.content_port,
                    peer.certificate_serial,
                ):
                    return False
                self._audit_event(
                    "address_changed", node_id=node.node_id,
                    node_name=node.name,
                    previous_address=f"{node.host}:{node.port}",
                    address=f"{target.host}:{target.content_port}",
                )
                self._log(
                    f"CLUSTER recovered endpoint for {node.name}: "
                    f"{node.host}:{node.port} -> "
                    f"{target.host}:{target.content_port}",
                    "ok",
                )
                return True
            except PeerCertificateSerialMismatch as error:
                self._audit_event(
                    "identity_conflict", node_id=node.node_id,
                    node_name=node.name,
                    address=f"{target.host}:{target.content_port}",
                    reason=type(error).__name__,
                )
                self._log(
                    f"CLUSTER identity conflict for {node.name} at "
                    f"{target.host}:{target.content_port}: {error}; "
                    "possible node impersonation or re-paired device under "
                    "same identity; manual re-pairing required",
                    "error",
                )
                return False
            except (PeerAuthorizationError, ConnectionError, OSError, ValueError) as error:
                self._log(
                    f"CLUSTER recovery probe failed for {node.name} at "
                    f"{target.host}:{target.content_port}: "
                    f"{type(error).__name__}: {error}",
                    "error",
                )
            finally:
                if secure is not None:
                    secure.close()
        return False

    def _update_discovered(self, nodes: tuple[DiscoveredNode, ...]) -> None:
        discovered: dict[tuple[str, str], BootstrapTarget] = {}
        discovered_created_at: dict[tuple[str, str], int] = {}
        pairing_open: set[tuple[str, str]] = set()
        nearby: dict[str, DiscoveredNode] = {}
        for node in nodes:
            if not node.node_id or node.node_id == self.node_id:
                continue
            existing = nearby.get(node.node_id)
            if existing is None or (node.pairing_open and not existing.pairing_open):
                nearby[node.node_id] = node
            if node.role != "slave":
                continue
            key = (node.node_id, node.window_id)
            for host in node.addresses:
                target = BootstrapTarget(
                    node_id=node.node_id, name=node.name or node.node_id,
                    host=host, bootstrap_port=node.port,
                    content_port=node.content_port, window_id=node.window_id,
                )
                discovered[key] = target
                discovered_created_at[key] = int(node.created_at or 0)
            if node.pairing_open:
                pairing_open.add(key)
        self._discovered = discovered
        self._discovered_created_at = discovered_created_at
        self._pairing_open = pairing_open
        self._nearby = nearby
        self._consider_superseding_master(tuple(nearby.values()))

    def replicate_p2p_relay_write(self, relay_id: str, relative_path: str, payload: bytes) -> int:
        runtime = self.runtime
        if isinstance(runtime, MasterClusterRuntime):
            return runtime.replicate_p2p_relay_write(relay_id, relative_path, payload)
        return 0

    def replicate_p2p_relay_delete(self, relay_id: str) -> int:
        runtime = self.runtime
        if isinstance(runtime, MasterClusterRuntime):
            return runtime.replicate_p2p_relay_delete(relay_id)
        return 0

    def nearby_nodes(self) -> tuple[DiscoveredNode, ...]:
        return tuple(sorted(self._nearby.values(), key=lambda value: (value.name.lower(), value.node_id)))

    def _resolve_target(self, node_id: str, window_id: str):
        key = (node_id, window_id)
        if key not in self._pairing_open:
            return None
        return self._discovered.get(key)

    def pairing_targets(self) -> dict:
        targets = []
        seen = set()
        for key in sorted(self._pairing_open):
            target = self._discovered.get(key)
            if target is None or target.node_id in seen or self.registry.get(target.node_id) is not None:
                continue
            seen.add(target.node_id)
            targets.append({
                "node_id": target.node_id, "name": target.name,
                "window_id": target.window_id,
            })
        targets.sort(key=lambda value: value["name"].lower())
        return {
            "targets": targets,
            "capacity": {
                "maximum": MAX_SLAVES,
                "used": len(self.registry.nodes),
                "available": max(0, MAX_SLAVES - len(self.registry.nodes)),
            },
        }

    def active_pairing_target(self) -> dict:
        target = self._active_pairing_target
        if target is None:
            return {}
        return {"node_id": target.node_id, "name": target.name, "window_id": target.window_id}

    def begin_pairing(self, node_id: str, window_id: str) -> None:
        if self.registry.get(node_id) is not None:
            raise RuntimeError("unlink the existing Slave before pairing again")
        if len(self.registry.nodes) >= MAX_SLAVES:
            raise RuntimeError("cluster_slave_limit_reached")
        target = self._resolve_target(node_id, window_id)
        if target is None:
            raise ValueError("pairing target unavailable")
        if self.ceremony is not None and not self.ceremony.closed:
            raise RuntimeError("pairing already active")
        self.ceremony = Ceremony()
        self._active_pairing_target = target
        self.pairing_error = ""
        def _run():
            try:
                enroll_sas(target=target, ceremony=self.ceremony,
                    master_store=self.identity_store, master_trust=self.trust,
                    registry=self.registry, signing_public_key=self._signing_public_key,
                    audience_generation=self.revocations.current_generation(target.node_id),
                    master_name=self.node_name, master_lan_url=self.master_lan_url,
                    target_created_at=self._discovered_created_at.get((target.node_id, target.window_id), 0))
                self.failover_authority.ensure_master_backup(
                    identity_store=self.identity_store, signing_private_key=self._signing_private_key,
                    leader_node_id=self.node_id, leader_epoch=self.leader_epoch,
                    roster=self._failover_roster(),
                )
                self._failover_synced.clear()
                self._audit_event(
                    "pairing", node_id=target.node_id, node_name=target.name,
                    address=f"{target.host}:{target.content_port}",
                )
            except Exception as error:
                self.pairing_error = str(error)
            finally:
                self._active_pairing_target = None
        threading.Thread(target=_run, daemon=True, name="netshare-cluster-sas-master").start()

    def confirm_pairing(self, matches: bool) -> None:
        if self.ceremony is None:
            raise RuntimeError("no pairing active")
        self.ceremony.decide(matches)

    def _connect_to(
        self, node_id: str, *, mark_failure: bool = True, mark_online: bool = True,
    ):
        node = self.registry.get(node_id)
        if node is None:
            raise ConnectionError("unknown cluster slave")
        try:
            secure, peer = connect_mutual_tls(
                (node.host, node.port), self.identity, self.trust,
                log=self._log,
            )
        except (PeerAuthorizationError, ConnectionError, OSError, ValueError):
            if mark_failure:
                self.registry.set_online(node_id, False)
            raise
        if peer.node_id != node_id:
            secure.close()
            raise ConnectionError("cluster peer identity mismatch")
        if mark_online:
            self.registry.set_online(node_id, True)
        return secure

    def _p2p_relay_store(self):
        from src.core.p2p_relay import P2PRelayStore
        config_dir = getattr(self, "config_dir", None)
        if config_dir is None:
            raise RuntimeError("cluster config directory unavailable")
        return P2PRelayStore(Path(config_dir).parent / ".netshare-p2p-relay")

    def replicate_p2p_relay_write(
        self, relay_id: str, relative_path: str, payload: bytes, *, node_id: str | None = None,
    ) -> int:
        """Best-effort mTLS replication of opaque relay bytes to trusted Slaves."""
        targets = [self.registry.get(node_id)] if node_id else list(self.registry.nodes)
        replicated = 0
        for node in targets:
            if node is None or not node.online:
                continue
            secure = None
            try:
                secure = self._connect_to(node.node_id, mark_failure=False, mark_online=False)
                request_relay_replica_write(
                    secure, relay_id=relay_id, relative_path=relative_path, payload=payload,
                )
                replicated += 1
            except (ConnectionError, OSError, ValueError) as error:
                self._log(
                    f"CLUSTER P2P relay replication deferred for {node.node_id}: "
                    f"{type(error).__name__}: {error}", "info",
                )
            finally:
                if secure is not None:
                    secure.close()
        return replicated

    def replicate_p2p_relay_delete(self, relay_id: str) -> int:
        replicated = 0
        for node in self.registry.nodes:
            if not node.online:
                continue
            secure = None
            try:
                secure = self._connect_to(node.node_id, mark_failure=False, mark_online=False)
                request_relay_replica_delete(secure, relay_id=relay_id)
                replicated += 1
            except (ConnectionError, OSError, ValueError):
                pass
            finally:
                if secure is not None:
                    secure.close()
        return replicated

    def sync_p2p_relays_to_node(self, node_id: str) -> int:
        count = 0
        try:
            files = self._p2p_relay_store().replica_files()
        except (OSError, ValueError, RuntimeError):
            return 0
        active_ids = sorted({relay_id for relay_id, _relative, _payload in files})
        secure = None
        try:
            secure = self._connect_to(node_id, mark_failure=False, mark_online=False)
            request_relay_replica_prune(secure, active_relay_ids=active_ids)
        except (ConnectionError, OSError, ValueError):
            return 0
        finally:
            if secure is not None:
                secure.close()
        for relay_id, relative_path, payload in files:
            count += self.replicate_p2p_relay_write(
                relay_id, relative_path, payload, node_id=node_id,
            )
        return count

    def remove_node(self, node_id: str) -> bool:
        cleanup_confirmed = False
        try:
            secure = self._connect_to(node_id)
            try:
                send_frame(secure, {"op": "UNPAIR"})
                cleanup_confirmed = receive_frame(secure).get("cleanup") == "confirmed"
            finally:
                secure.close()
        except (ConnectionError, OSError, ValueError):
            cleanup_confirmed = False
        removed = self.registry.remove(node_id)
        if removed:
            self._heartbeat_failures.pop(node_id, None)
            self._heartbeat_next_attempt.pop(node_id, None)
            self._heartbeat_states.pop(node_id, None)
            self._node_media_capabilities.pop(node_id, None)
            self.trust.revoke(node_id)
            self.revocations.revoke_node(node_id)
            self.last_unpair_status = (
                "cleanup_confirmed" if cleanup_confirmed
                else "access_revoked_cleanup_unconfirmed"
            )
            self.failover_authority.ensure_master_backup(
                identity_store=self.identity_store, signing_private_key=self._signing_private_key,
                leader_node_id=self.node_id, leader_epoch=self.leader_epoch,
                roster=self._failover_roster(),
                ticket_generations=self._ticket_generations_snapshot(),
            )
            self._failover_synced.clear()
            self._audit_event(
                "unlink", node_id=node_id, cleanup_status=self.last_unpair_status,
            )
        return removed

    def _consider_superseding_master(self, nodes: tuple[DiscoveredNode, ...]) -> None:
        if self._supersede_probe_active:
            return
        own_rank = election_rank(self.node_created_at, self.node_id)
        candidates = []
        for node in nodes:
            if node.role != "master" or node.node_id == self.node_id:
                continue
            if self.registry.get(node.node_id) is None:
                continue
            candidate_rank = election_rank(node.created_at, node.node_id)
            if node.leader_epoch > self.leader_epoch or (
                node.leader_epoch == self.leader_epoch and candidate_rank < own_rank
            ):
                candidates.append(node)
        if not candidates:
            return
        candidates.sort(key=lambda n: (-n.leader_epoch, election_rank(n.created_at, n.node_id)))
        candidate = candidates[0]
        self._supersede_probe_active = True

        def _probe():
            try:
                response = probe_leader(
                    host=candidate.addresses[0], port=candidate.content_port,
                    identity=self.identity, trust_store=self.trust,
                    expected_node_id=candidate.node_id, log=self._log,
                )
                epoch = int(response.get("leader_epoch", 0) or 0)
                if epoch >= candidate.leader_epoch and epoch > 0:
                    self._log(
                        f"CLUSTER authenticated newer leader {candidate.name or candidate.node_id} "
                        f"epoch={epoch}; stepping down", "info",
                    )
                    self._on_superseded(candidate.node_id, epoch)
            except (OSError, ValueError, PermissionError, PeerAuthorizationError) as error:
                self._log(
                    f"CLUSTER ignored unverified leader claim from {candidate.node_id}: "
                    f"{type(error).__name__}: {error}", "error",
                )
            finally:
                self._supersede_probe_active = False
        threading.Thread(target=_probe, daemon=True, name="netshare-cluster-leader-verify").start()

    def prepare_failover_demotion(self, new_leader_node_id: str, new_epoch: int) -> None:
        self.failover_authority.update_metadata(
            roster=self._failover_roster(),
            ticket_generations=self._ticket_generations_snapshot(),
        )
        self.failover_authority.prepare_demoted_master(
            identity_store=self.identity_store, key_store=self.key_store,
            new_leader_node_id=new_leader_node_id, new_epoch=new_epoch,
        )

    def stop(self) -> None:
        self._heartbeat_stop.set()
        self.browser.stop()
        self.presence_advertiser.stop()
        if self.leader_listener is not None:
            self.leader_listener.stop()
            self.leader_listener = None
        thread, self._heartbeat_thread = self._heartbeat_thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)


class SlaveClusterRuntime:
    def __init__(
        self, *, config_dir: Path, roots: tuple, backend: SecureKeyBackend,
        node_id: str, node_name: str, addresses: list[str],
        bootstrap_port: int, content_port: int, node_created_at: int | float = 0,
        on_fallback_change=lambda _enabled, _metadata: None,
        on_failover_promote=lambda _epoch: None, auto_failover: bool = False,
        log=lambda _message, _kind="info": None,
    ):
        self.config_dir = config_dir / "cluster"
        self.roots = roots
        self.node_id = node_id or uuid.uuid4().hex
        self.node_name = node_name
        self.addresses = addresses
        self.bootstrap_port = int(bootstrap_port)
        self.content_port = int(content_port)
        self.node_created_at = int(float(node_created_at or 0))
        self._log = log
        self._on_fallback_change = _safe_callback(on_fallback_change, _noop_fallback_change)
        self._on_failover_promote = _safe_callback(on_failover_promote, lambda _epoch: None)
        self.auto_failover = bool(auto_failover)
        self.backend = backend
        self.failover_authority = FailoverAuthorityStore(config_dir, backend)
        self._failover_stop = threading.Event()
        self._failover_thread = None
        self._verifier = None
        if not 1 <= self.content_port <= 65535:
            raise ValueError("slave content port must be fixed before discovery")
        self.store = ClusterIdentityStore(config_dir, backend)
        self.trust_path = self.config_dir / "trusted_peers.json"
        self.ceremony = None
        self.pairing_error = ""
        self.last_unpair_status = ""
        self.advertiser = DiscoveryAdvertiser(addresses)
        self.presence_advertiser = DiscoveryAdvertiser(addresses)
        self.browser = DiscoveryBrowser()
        self._nearby: dict[str, DiscoveredNode] = {}
        self._bootstrap_listener: socket.socket | None = None
        self._bootstrap_thread: threading.Thread | None = None
        self.file_listener: ClusterFileListener | None = None
        # Keep one live trust-store instance for the lifetime of the Slave
        # listener.  The listener holds a reference to this object, so failover
        # roster updates must mutate the same instance instead of creating a
        # second PeerTrustStore that only updates the on-disk registry.
        self.trust: PeerTrustStore | None = None
        self.fallback = SlaveFallbackState(
            self.config_dir / "master_connection.json",
            on_change=self._handle_fallback_change,
        )

    def start(self) -> None:
        """Restore a previously joined Slave and advertise passive LAN presence."""
        if self.addresses:
            self.presence_advertiser.start(
                self.content_port, role="slave", content_port=self.content_port,
                node_id=self.node_id, name=self.node_name, pairing_open=False,
                created_at=self.node_created_at, leader_epoch=self.failover_authority.leader_epoch, duration_seconds=None,
            )
        self.browser.start(self._update_discovered)
        if self.store.exists("slave"):
            self.fallback.arm_linked()
            self.fallback.start()
            self._start_file_listener()

    def start_pairing(self) -> dict:
        if self._bootstrap_listener is not None:
            raise RuntimeError("cluster bootstrap is already active")
        if self.store.exists("slave"):
            raise RuntimeError("unlink this Slave locally before pairing again")
        self.ceremony = Ceremony()
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", self.bootstrap_port))
        listener.listen(5)
        listener.settimeout(0.5)
        self._bootstrap_listener = listener
        self.bootstrap_port = int(listener.getsockname()[1])
        window_id = self.advertiser.start(
            self.bootstrap_port, role="slave", content_port=self.content_port,
            node_id=self.node_id, name=self.node_name, pairing_open=True,
            created_at=self.node_created_at,
        )
        self._bootstrap_thread = threading.Thread(
            target=self._serve_bootstrap, args=(window_id,), daemon=True,
            name="netshare-cluster-bootstrap",
        )
        self._bootstrap_thread.start()
        return {"node_id": self.node_id, "window_id": window_id,
                "expires_at": self.ceremony.expires_at}

    def _update_discovered(self, nodes: tuple[DiscoveredNode, ...]) -> None:
        nearby: dict[str, DiscoveredNode] = {}
        for node in nodes:
            if not node.node_id or node.node_id == self.node_id:
                continue
            existing = nearby.get(node.node_id)
            if existing is None or (node.pairing_open and not existing.pairing_open):
                nearby[node.node_id] = node
        self._nearby = nearby

    def nearby_nodes(self) -> tuple[DiscoveredNode, ...]:
        return tuple(sorted(self._nearby.values(), key=lambda value: (value.name.lower(), value.node_id)))

    def _serve_bootstrap(self, window_id: str) -> None:
        target = BootstrapTarget(
            node_id=self.node_id, name=self.node_name,
            host=self.addresses[0] if self.addresses else "",
            bootstrap_port=self.bootstrap_port, content_port=self.content_port,
            window_id=window_id,
        )
        session = SlaveSasSession(
            store=self.store, trust_path=self.trust_path,
            target=target, ceremony=self.ceremony,
            on_master_authenticated=self.fallback.record_authenticated_master,
        )
        while self.ceremony is not None and not self.ceremony.closed:
            try:
                raw, _address = self._bootstrap_listener.accept()
            except (OSError, TimeoutError):
                continue
            try:
                session.handle(raw)
            except (OSError, ValueError) as error:
                self.pairing_error = str(error)
                raw.close()
        self.advertiser.stop()
        listener, self._bootstrap_listener = self._bootstrap_listener, None
        if listener is not None:
            listener.close()
        if self.store.exists("slave"):
            self.fallback.arm_linked()
            self.fallback.start()
            self._start_file_listener()

    def confirm_pairing(self, matches: bool) -> None:
        if self.ceremony is None:
            raise RuntimeError("no pairing active")
        self.ceremony.decide(matches)

    def _start_file_listener(self) -> None:
        identity = self.store.load_identity()
        trust = PeerTrustStore(self.trust_path, identity.ca_fingerprint)
        self.failover_authority.sync_trust_store(trust, local_node_id=self.node_id)
        self.trust = trust
        public_key = (self.config_dir / "master_signing_key.bin").read_bytes()
        revocations = RevocationRegistry(self.config_dir / "revocations.json")
        issuer = self.failover_authority.leader_node_id
        if not issuer or issuer == self.node_id:
            candidates = [value for value in trust.node_ids if value != self.node_id]
            issuer = candidates[0] if candidates else ""
        if not issuer:
            raise RuntimeError("cluster Master identity is unavailable")
        self._verifier = TicketVerifier(
            public_key, revocations, cluster_id=identity.cluster_id,
            issuer_node_id=issuer, log=self._log,
        )
        protocol = SlaveFileProtocol(
            roots=self.roots, node_id=identity.node_id,
            verifier=self._verifier,
            protected_check=lambda path: (
                unlock_codes.find_governing_premium_folder(path) is not None
            ),
            access_check=lambda path, device_id: not unlock_codes.lock_status_for_path(
                path, device_id,
            )["locked"],
            cursor_codec=ListingCursorCodec(
                self.store.load_node_private_key(), node_id=identity.node_id,
            ),
            unpair_callback=self._unpair_local,
            heartbeat_callback=self._record_authenticated_heartbeat,
            derived_service=derived_media_service,
            relay_replica_write=self._write_p2p_relay_replica,
            relay_replica_delete=self._delete_p2p_relay_replica,
            relay_replica_prune=self._prune_p2p_relay_replicas,
        )
        self.file_listener = ClusterFileListener(
            host="0.0.0.0", port=self.content_port,
            identity=identity, trust_store=trust, protocol=protocol,
            log=self._log,
        )
        self.content_port = self.file_listener.start()


    def _p2p_relay_store(self):
        from src.core.p2p_relay import P2PRelayStore
        return P2PRelayStore(self.config_dir.parent / ".netshare-p2p-relay")

    def _write_p2p_relay_replica(self, relay_id: str, relative_path: str, payload: bytes) -> None:
        self._p2p_relay_store().replica_write(
            relay_id=relay_id, relative_path=relative_path, data=payload,
        )

    def _delete_p2p_relay_replica(self, relay_id: str) -> None:
        self._p2p_relay_store().replica_delete(relay_id)

    def _prune_p2p_relay_replicas(self, active_relay_ids: list[str]) -> None:
        self._p2p_relay_store().replica_prune(active_relay_ids)

    def _handle_fallback_change(self, enabled: bool, metadata: dict) -> None:
        self._on_fallback_change(enabled, metadata)
        if enabled and self.auto_failover and self.store.exists("slave") and self.failover_authority.ready:
            self._ensure_failover_election()
        if not enabled or not self.store.exists("slave") or self.advertiser.active:
            return
        try:
            self.advertiser.start(
                self.content_port, role="slave", content_port=self.content_port,
                node_id=self.node_id, name=self.node_name, pairing_open=False,
                created_at=self.node_created_at,
            )
            self._log(
                "CLUSTER Slave recovery discovery advertised", "info",
            )
        except (OSError, RuntimeError, ValueError) as error:
            self._log(
                f"CLUSTER Slave recovery discovery unavailable: "
                f"{type(error).__name__}: {error}",
                "error",
            )
    def _record_authenticated_heartbeat(self, request: dict, authenticated_peer_id: str) -> dict:
        payload = request.get("failover")
        if isinstance(payload, dict):
            leader = str(payload.get("leader_node_id") or authenticated_peer_id)
            epoch = max(0, int(payload.get("leader_epoch", 0) or 0))
            roster = payload.get("roster") if isinstance(payload.get("roster"), list) else []
            authority = payload.get("authority")
            ticket_generations = (
                payload.get("ticket_generations")
                if isinstance(payload.get("ticket_generations"), dict) else None
            )
            if isinstance(authority, dict) and authority:
                self.failover_authority.import_transport_bundle(
                    authority, identity_store=self.store, leader_node_id=leader,
                    leader_epoch=epoch, roster=roster,
                    ticket_generations=ticket_generations,
                )
            else:
                self.failover_authority.update_metadata(
                    authority_version=str(payload.get("authority_version") or self.failover_authority.authority_version),
                    leader_node_id=leader, leader_epoch=epoch, roster=roster,
                    ticket_generations=ticket_generations,
                )
            # Synchronize the trust store that is actually used by the active
            # ClusterFileListener.  Re-opening the JSON file into a new object
            # here updates disk but leaves the listener with stale in-memory
            # peers, which makes a legitimately promoted AUTO Master fail mTLS
            # with "peer certificate is not authorized".
            trust = self.trust
            if trust is None:
                identity = self.store.load_identity()
                trust = PeerTrustStore(self.trust_path, identity.ca_fingerprint)
                self.trust = trust
            self.failover_authority.sync_trust_store(trust, local_node_id=self.node_id)
            if self._verifier is not None and authenticated_peer_id == self._verifier.issuer_node_id:
                self._verifier.set_issuer_node_id(leader)
        self.fallback.record_authenticated_master(
            str(request.get("master_name", "")),
            str(request.get("master_url", "")),
        )
        local_generation = 0
        if self._verifier is not None:
            local_generation = self._verifier.revocations.current_generation(self.node_id)
        return {
            "failover_version": self.failover_authority.authority_version,
            "ticket_generation": local_generation,
            "media_capabilities": _local_media_capabilities(),
        }

    def _ensure_failover_election(self) -> None:
        if self._failover_thread is not None and self._failover_thread.is_alive():
            return
        self._failover_stop.clear()
        self._failover_thread = threading.Thread(
            target=self._failover_election_loop, daemon=True,
            name="netshare-cluster-failover-election",
        )
        self._failover_thread.start()

    def _failover_election_loop(self) -> None:
        if self._failover_stop.wait(FAILOVER_ELECTION_GRACE_SECONDS):
            return
        election_started = time.monotonic()
        while not self._failover_stop.is_set() and self.fallback.direct_http_enabled():
            roster = {node.node_id: node for node in self.failover_authority.roster}
            if self.node_id not in roster:
                self._log("CLUSTER failover blocked: local node missing from authenticated roster", "error")
                return
            identity = self.store.load_identity()
            trust = PeerTrustStore(self.trust_path, identity.ca_fingerprint)
            nearby = tuple(self._nearby.values())
            # Prefer an already-promoted, authenticated roster member.
            leaders = [
                node for node in nearby
                if node.role == "master" and node.node_id in roster
                and node.node_id != self.node_id
                and node.leader_epoch >= self.failover_authority.leader_epoch + 1
            ]
            leaders.sort(key=lambda n: (-n.leader_epoch, election_rank(n.created_at, n.node_id)))
            for leader in leaders:
                try:
                    response = probe_leader(
                        host=leader.addresses[0], port=leader.content_port,
                        identity=identity, trust_store=trust,
                        expected_node_id=leader.node_id, log=self._log,
                    )
                    epoch = int(response.get("leader_epoch", 0) or 0)
                    if epoch < leader.leader_epoch:
                        continue
                    self.failover_authority.update_metadata(
                        leader_node_id=leader.node_id, leader_epoch=epoch,
                    )
                    if self._verifier is not None:
                        self._verifier.set_issuer_node_id(leader.node_id)
                    self._log(
                        f"CLUSTER failover following authenticated leader "
                        f"{leader.name or leader.node_id} epoch={epoch}", "ok",
                    )
                    return
                except (OSError, ValueError, PermissionError, PeerAuthorizationError):
                    continue
            visible = {self.node_id}
            for node in nearby:
                if node.role == "slave" and node.node_id in roster:
                    visible.add(node.node_id)
            required = quorum_required(len(roster))
            trusted_master_visible = any(
                node.role == "master" and node.node_id in roster
                for node in nearby
            )
            witnessless_two_node = (
                len(roster) == 2 and visible == {self.node_id}
                and not trusted_master_visible
                and time.monotonic() - election_started >= TWO_NODE_WITNESSLESS_AFTER_SECONDS
            )
            if len(visible) < required and not witnessless_two_node:
                self._log(
                    f"CLUSTER failover waiting for quorum: {len(visible)}/{required} "
                    f"visible trusted member(s)", "info",
                )
                if self._failover_stop.wait(10.0):
                    return
                continue
            if witnessless_two_node:
                self._log(
                    "CLUSTER two-node failover: Master absent from mDNS for extended "
                    "timeout; using witnessless promotion with epoch fencing", "info",
                )
            candidates = [roster[node_id] for node_id in visible if node_id in roster]
            candidates.sort(key=lambda node: election_rank(node.created_at, node.node_id))
            winner = candidates[0]
            new_epoch = self.failover_authority.leader_epoch + 1
            self.failover_authority.update_metadata(
                leader_node_id=winner.node_id, leader_epoch=new_epoch,
            )
            if winner.node_id == self.node_id:
                self._log(
                    f"CLUSTER failover quorum reached; promoting local node "
                    f"to MASTER epoch={new_epoch}", "ok",
                )
                self._on_failover_promote(new_epoch)
                return
            if self._verifier is not None:
                self._verifier.set_issuer_node_id(winner.node_id)
            self._log(
                f"CLUSTER failover elected {winner.name or winner.node_id} as MASTER "
                f"epoch={new_epoch}; waiting for authenticated leader probe", "info",
            )
            if self._failover_stop.wait(10.0):
                return

    def prepare_failover_promotion(self, new_epoch: int) -> None:
        self.failover_authority.promote_local(
            identity_store=self.store, key_store=ClusterKeyStore(self.backend),
            local_node_id=self.node_id, new_epoch=new_epoch,
        )

    def direct_http_enabled(self) -> bool:
        return self.store.exists("slave") and self.fallback.direct_http_enabled()

    def fallback_payload(self) -> dict:
        return self.fallback.metadata if self.direct_http_enabled() else {}

    def _unpair_local(self) -> None:
        listener, self.file_listener = self.file_listener, None
        if listener is not None:
            listener.stop()
        self.trust = None
        self.fallback.clear_relation()
        self.fallback.stop()
        self.failover_authority.clear()
        self.store.delete_joined_identity()
        self.last_unpair_status = "cleanup_confirmed"

    def unpair_local(self) -> None:
        """Explicit Slave-side cleanup for an offline Master revocation."""
        self._unpair_local()

    def stop(self) -> None:
        self._failover_stop.set()
        thread, self._failover_thread = self._failover_thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
        self.fallback.stop()
        self.advertiser.stop()
        self.presence_advertiser.stop()
        self.browser.stop()
        listener, self._bootstrap_listener = self._bootstrap_listener, None
        if listener is not None:
            listener.close()
        if self.file_listener is not None:
            self.file_listener.stop()
            self.file_listener = None
        self.trust = None


class ClusterRuntimeManager:
    """Own one local role, with a mandatory fail-closed feature gate.

    AUTO preserves established trust: a joined Slave stays a Slave and a Master
    with registered Slaves stays Master.  An unlinked/orphan Master identity is
    allowed to re-enter deterministic mDNS election so earlier manual role tests
    cannot permanently force multiple AUTO nodes to become Masters.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._context = {}
        self.runtime = None
        self.controller = None
        self.relay = None
        self.configured_role = "standalone"
        self.effective_role = "standalone"
        self._on_runtime_change = lambda _controller, _relay, _role: None

    def _publish_runtime_change(self) -> None:
        """Publish the currently active controller/relay after a role change.

        AUTO failover replaces the runtime in-place.  HTTP routes historically
        received a snapshot of ``manager.controller``/``manager.relay`` only at
        server startup, so a promoted Slave could be a healthy Master while the
        Player-facing routes still queried the old empty Slave controller.
        """
        callback = self._on_runtime_change
        try:
            callback(self.controller, self.relay, self.effective_role)
        except Exception:
            # Runtime transitions must fail closed on their own invariants; a
            # UI/state publication hook is not allowed to tear down the cluster.
            pass

    def start(
        self, *, feature_enabled: bool, role: str, config_dir: Path,
        roots,
        node_id: str, node_name: str,
        addresses: list[str], base_port: int, node_created_at: int | float = 0,
        on_node_change=lambda _node_id, _name, _online: None,
        on_fallback_change=lambda _enabled, _metadata: None,
        on_runtime_change=lambda _controller, _relay, _role: None,
        log=lambda _message, _kind="info": None,
    ) -> None:
        self.stop()
        self._on_runtime_change = _safe_callback(
            on_runtime_change, lambda _controller, _relay, _role: None,
        )
        self.configured_role = str(role)
        self.effective_role = "standalone"
        on_node_change = _safe_callback(on_node_change, _noop_node_change)
        on_fallback_change = _safe_callback(on_fallback_change, _noop_fallback_change)
        self._context = {
            "feature_enabled": feature_enabled, "role": str(role),
            "config_dir": config_dir, "roots": roots, "node_id": node_id,
            "node_name": node_name, "addresses": list(addresses),
            "base_port": int(base_port), "node_created_at": node_created_at,
            "on_node_change": on_node_change,
            "on_fallback_change": on_fallback_change, "log": log,
        }
        if feature_enabled is not True:
            if role != "standalone":
                raise PermissionError("cluster feature flag is disabled")
            return
        if role == "standalone":
            return
        backend = default_backend(config_dir)
        effective = str(role)
        if effective == "auto":
            store = ClusterIdentityStore(config_dir, backend)
            # A joined Slave owns trust issued by its Master and must not silently
            # rewrite that relationship merely because mDNS disappeared for a
            # moment.  It stays pinned until the explicit local UNLINK action.
            if store.exists("slave"):
                effective = "slave"
                log("CLUSTER AUTO retained linked SLAVE identity", "info")
            else:
                master_exists = store.exists("master")
                registered = ()
                if master_exists:
                    try:
                        registered = ClusterRegistry(
                            config_dir / "cluster" / "nodes.json"
                        ).nodes
                    except (OSError, ValueError):
                        registered = ()

                # An established Master that still owns trusted Slaves is an
                # existing cluster, not an election candidate.  Keep it stable
                # and advertise immediately so fresh AUTO peers can join it.
                if master_exists and registered:
                    effective = "master"
                    log(
                        f"CLUSTER AUTO retained MASTER with "
                        f"{len(registered)} registered Slave(s)",
                        "info",
                    )
                else:
                    # Previous manual MASTER tests can leave an otherwise
                    # unlinked Master identity behind.  Such an orphan must not
                    # force every AUTO node to become Master forever.  Re-run
                    # the deterministic LAN election even when that identity
                    # exists; if this node loses, release only the orphaned local
                    # Master material before becoming a Slave.
                    discovered = scan_for_auto_election(
                        addresses=addresses, port=base_port, node_id=node_id,
                        name=node_name, created_at=node_created_at,
                    )
                    effective = choose_auto_role(
                        local_node_id=node_id, local_created_at=node_created_at,
                        discovered=discovered,
                    )
                    if effective == "slave" and master_exists:
                        store.delete_joined_identity()
                        ClusterKeyStore(backend).delete_private_key()
                        (config_dir / "cluster" / "nodes.json").unlink(missing_ok=True)
                        log(
                            "CLUSTER AUTO released orphan MASTER identity after "
                            "losing deterministic election",
                            "info",
                        )
            log(f"CLUSTER AUTO elected local role: {effective.upper()}", "info")
        if effective == "master":
            master_host = addresses[0] if addresses else ""
            runtime = MasterClusterRuntime(
                config_dir=config_dir, root=roots[0].path, backend=backend,
                node_id=node_id, node_name=node_name, addresses=addresses,
                discovery_port=base_port, node_created_at=node_created_at,
                master_lan_url=(
                    f"http://{master_host}:{base_port}" if master_host else ""
                ),
                on_node_change=on_node_change,
                on_superseded=self._handle_master_superseded, log=log,
            )
            runtime.start()
            self.runtime = runtime
            self.controller = runtime.control
            self.relay = runtime.relay
            self.effective_role = "master"
            self._publish_runtime_change()
            return
        if effective == "slave":
            runtime = SlaveClusterRuntime(
                config_dir=config_dir, roots=roots, backend=backend,
                node_id=node_id, node_name=node_name, addresses=addresses,
                bootstrap_port=base_port + 3, content_port=base_port + 4,
                node_created_at=node_created_at,
                on_fallback_change=on_fallback_change,
                on_failover_promote=self._handle_slave_promotion,
                auto_failover=(str(role) == "auto"), log=log,
            )
            runtime.start()
            self.runtime = runtime
            self.controller = ClusterControlService(
                ClusterRegistry(runtime.config_dir / "nodes.json"),
            )
            self.relay = None
            self.effective_role = "slave"
            self._publish_runtime_change()
            return
        raise ValueError("invalid cluster role")

    def _handle_slave_promotion(self, new_epoch: int) -> None:
        source = self.runtime
        if not isinstance(source, SlaveClusterRuntime) or self.configured_role != "auto":
            return
        threading.Thread(
            target=self._promote_slave, args=(source, int(new_epoch)), daemon=True,
            name="netshare-cluster-promote",
        ).start()

    def _promote_slave(self, source: SlaveClusterRuntime, new_epoch: int) -> None:
        with self._lock:
            if self.runtime is not source or self.configured_role != "auto":
                return
            ctx = dict(self._context)
            log = ctx.get("log", lambda _m, _k="info": None)
            try:
                source.prepare_failover_promotion(new_epoch)
                source.stop()
                backend = default_backend(ctx["config_dir"])
                master_host = ctx["addresses"][0] if ctx["addresses"] else ""
                runtime = MasterClusterRuntime(
                    config_dir=ctx["config_dir"], root=ctx["roots"][0].path,
                    backend=backend, node_id=ctx["node_id"],
                    node_name=ctx["node_name"], addresses=ctx["addresses"],
                    discovery_port=ctx["base_port"],
                    node_created_at=ctx["node_created_at"],
                    master_lan_url=(
                        f"http://{master_host}:{ctx['base_port']}" if master_host else ""
                    ),
                    on_node_change=ctx["on_node_change"],
                    on_superseded=self._handle_master_superseded, log=log,
                )
                runtime.leader_epoch = max(runtime.leader_epoch, int(new_epoch))
                runtime.failover_authority.update_metadata(
                    leader_node_id=ctx["node_id"], leader_epoch=runtime.leader_epoch,
                )
                runtime.start()
                self.runtime = runtime
                self.controller = runtime.control
                self.relay = runtime.relay
                self.effective_role = "master"
                self._publish_runtime_change()
                log(
                    f"CLUSTER FAILOVER complete: local node is MASTER "
                    f"epoch={runtime.leader_epoch}", "ok",
                )
            except Exception as error:
                log(
                    f"CLUSTER FAILOVER promotion failed: {type(error).__name__}: {error}",
                    "error",
                )

    def _handle_master_superseded(self, node_id: str, epoch: int) -> None:
        source = self.runtime
        if not isinstance(source, MasterClusterRuntime) or self.configured_role != "auto":
            return
        threading.Thread(
            target=self._demote_master, args=(source, str(node_id), int(epoch)),
            daemon=True, name="netshare-cluster-demote",
        ).start()

    def _demote_master(
        self, source: MasterClusterRuntime, new_leader_node_id: str, new_epoch: int,
    ) -> None:
        with self._lock:
            if self.runtime is not source or self.configured_role != "auto":
                return
            ctx = dict(self._context)
            log = ctx.get("log", lambda _m, _k="info": None)
            try:
                source.stop()
                source.prepare_failover_demotion(new_leader_node_id, new_epoch)
                backend = default_backend(ctx["config_dir"])
                runtime = SlaveClusterRuntime(
                    config_dir=ctx["config_dir"], roots=ctx["roots"], backend=backend,
                    node_id=ctx["node_id"], node_name=ctx["node_name"],
                    addresses=ctx["addresses"],
                    bootstrap_port=ctx["base_port"] + 3,
                    content_port=ctx["base_port"] + 4,
                    node_created_at=ctx["node_created_at"],
                    on_fallback_change=ctx["on_fallback_change"],
                    on_failover_promote=self._handle_slave_promotion,
                    auto_failover=True, log=log,
                )
                runtime.start()
                if runtime._verifier is not None:
                    runtime._verifier.set_issuer_node_id(new_leader_node_id)
                self.runtime = runtime
                self.controller = ClusterControlService(
                    ClusterRegistry(runtime.config_dir / "nodes.json"),
                )
                self.relay = None
                self.effective_role = "slave"
                self._publish_runtime_change()
                log(
                    f"CLUSTER FAILOVER stepped down to SLAVE; leader={new_leader_node_id} "
                    f"epoch={new_epoch}", "ok",
                )
            except Exception as error:
                self.runtime = None
                self.controller = None
                self.relay = None
                self.effective_role = "standalone"
                self._publish_runtime_change()
                log(
                    f"CLUSTER FAILOVER demotion failed closed: "
                    f"{type(error).__name__}: {error}", "error",
                )

    def nearby_nodes(self) -> tuple[DiscoveredNode, ...]:
        runtime = self.runtime
        getter = getattr(runtime, "nearby_nodes", None)
        if callable(getter):
            return tuple(getter())
        return ()

    def stop(self) -> None:
        runtime, self.runtime = self.runtime, None
        self.controller = None
        self.relay = None
        self.effective_role = "standalone"
        self._publish_runtime_change()
        if runtime is not None:
            runtime.stop()

