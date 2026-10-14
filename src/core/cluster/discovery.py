"""Untrusted, bounded DNS-SD hints for opt-in cluster discovery.

mDNS is discovery-only.  Every actual cluster enrollment still goes through the
TLS 1.3 + SAS bootstrap before any peer becomes trusted.
"""

from __future__ import annotations

import ipaddress
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from src.deps import HAS_ZEROCONF

SERVICE_TYPE = "_netshare-node._tcp.local."
DISCOVERY_WINDOW_SECONDS = 5 * 60
AUTO_ELECTION_SCAN_SECONDS = 2.8
MAX_DISCOVERED_NODES = 32
MAX_TXT_VALUE_BYTES = 64
PROTOCOL_VERSION = "1"


class DiscoveryUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class DiscoveredNode:
    instance: str
    addresses: tuple[str, ...]
    port: int
    role: str
    protocol_version: str
    window_id: str
    content_port: int = 0
    node_id: str = ""
    name: str = ""
    pairing_open: bool = True
    created_at: int = 0
    leader_epoch: int = 0


def _zeroconf_types():
    if not HAS_ZEROCONF:
        raise DiscoveryUnavailable("python-zeroconf is not installed")
    from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf
    return ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf


def _is_local_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return not address.is_loopback and (address.is_private or address.is_link_local)


class DiscoveryAdvertiser:
    """Advertise an untrusted LAN hint.

    ``pairing_open`` differentiates a persistent presence advertisement from a
    short-lived Slave bootstrap window.  Older peers that do not send the flag
    are treated as pairing-open for backwards compatibility.
    """

    def __init__(self, addresses: list[str], timer_factory=threading.Timer):
        self.addresses = tuple(address for address in addresses if _is_local_address(address))
        self.timer_factory = timer_factory
        self._zeroconf = None
        self._info = None
        self._timer = None

    @property
    def active(self) -> bool:
        return self._zeroconf is not None

    def start(
        self, port: int, role: str = "master", content_port: int = 0,
        node_id: str = "", name: str = "", *, pairing_open: bool = True,
        created_at: int | float = 0, leader_epoch: int = 0, duration_seconds: float | None = DISCOVERY_WINDOW_SECONDS,
    ) -> str:
        if self._zeroconf is not None:
            raise RuntimeError("discovery is already active")
        if not self.addresses or not 1 <= int(port) <= 65535:
            raise ValueError("invalid discovery endpoint")
        if role not in ("master", "slave", "auto"):
            raise ValueError("invalid discovery role")
        if content_port and not 1 <= int(content_port) <= 65535:
            raise ValueError("invalid cluster content endpoint")
        if node_id and (len(node_id) > 64 or not node_id.replace("-", "").replace("_", "").isalnum()):
            raise ValueError("invalid discovery node identity")
        born = max(0, int(float(created_at or 0)))
        _browser, ServiceInfo, _listener, Zeroconf = _zeroconf_types()
        window_id = secrets.token_hex(8)
        properties = {
            "v": PROTOCOL_VERSION,
            "role": role,
            "window": window_id,
            "content": str(int(content_port or port)),
            "node": node_id,
            "name": name[:MAX_TXT_VALUE_BYTES],
            "open": "1" if pairing_open else "0",
            "born": str(born),
            "epoch": str(max(0, int(leader_epoch or 0))),
        }
        self._zeroconf = Zeroconf()
        self._info = ServiceInfo(
            SERVICE_TYPE,
            f"NetShare-{window_id}.{SERVICE_TYPE}",
            parsed_addresses=list(self.addresses),
            port=int(port),
            properties=properties,
        )
        self._zeroconf.register_service(self._info, ttl=30, allow_name_change=False)
        if duration_seconds is not None:
            duration = max(1.0, float(duration_seconds))
            self._timer = self.timer_factory(duration, self.stop)
            self._timer.daemon = True
            self._timer.start()
        return window_id

    def stop(self) -> None:
        timer, self._timer = self._timer, None
        if timer is not None and timer is not threading.current_thread():
            timer.cancel()
        zeroconf, info = self._zeroconf, self._info
        self._zeroconf = None
        self._info = None
        if zeroconf is not None:
            try:
                if info is not None:
                    zeroconf.unregister_service(info)
            finally:
                zeroconf.close()


class DiscoveryBrowser:
    def __init__(self):
        self._zeroconf = None
        self._browser = None
        self._nodes: dict[str, DiscoveredNode] = {}

    def start(self, on_update: Callable[[tuple[DiscoveredNode, ...]], None]) -> None:
        if self._zeroconf is not None:
            raise RuntimeError("discovery browser is already active")
        ServiceBrowser, _info, ServiceListener, Zeroconf = _zeroconf_types()
        owner = self

        class Listener(ServiceListener):
            def add_service(self, zc, type_, name):
                owner._update(zc, type_, name, on_update)

            def update_service(self, zc, type_, name):
                owner._update(zc, type_, name, on_update)

            def remove_service(self, _zc, _type, name):
                owner._nodes.pop(name, None)
                on_update(owner.nodes)

        self._zeroconf = Zeroconf()
        self._browser = ServiceBrowser(self._zeroconf, SERVICE_TYPE, Listener())

    @property
    def nodes(self) -> tuple[DiscoveredNode, ...]:
        return tuple(sorted(self._nodes.values(), key=lambda value: value.instance))

    def stop(self) -> None:
        browser, self._browser = self._browser, None
        zeroconf, self._zeroconf = self._zeroconf, None
        if browser is not None:
            browser.cancel()
        if zeroconf is not None:
            zeroconf.close()
        self._nodes.clear()

    def _update(self, zeroconf, type_: str, name: str, on_update) -> None:
        if name not in self._nodes and len(self._nodes) >= MAX_DISCOVERED_NODES:
            return
        info = zeroconf.get_service_info(type_, name, timeout=500)
        if info is None:
            return
        properties = {}
        for raw_key, raw_value in info.properties.items():
            if not isinstance(raw_key, bytes) or not isinstance(raw_value, bytes):
                return
            if len(raw_key) > MAX_TXT_VALUE_BYTES or len(raw_value) > MAX_TXT_VALUE_BYTES:
                return
            try:
                properties[raw_key.decode("ascii")] = raw_value.decode("ascii")
            except UnicodeDecodeError:
                return
        if properties.get("v") != PROTOCOL_VERSION:
            return
        role = properties.get("role", "")
        window_id = properties.get("window", "")
        node_id = properties.get("node", "")
        node_name = properties.get("name", "")
        if role not in ("master", "slave", "auto") or len(window_id) != 16:
            return
        if node_id and (len(node_id) > 64 or not node_id.replace("-", "").replace("_", "").isalnum()):
            return
        try:
            content_port = int(properties.get("content", "0"))
            born = max(0, int(properties.get("born", "0") or "0"))
            epoch = max(0, int(properties.get("epoch", "0") or "0"))
        except ValueError:
            return
        pairing_open = properties.get("open", "1") == "1"
        addresses = tuple(
            address for address in info.parsed_addresses() if _is_local_address(address)
        )
        if (
            not addresses or not 1 <= int(info.port or 0) <= 65535
            or not 1 <= content_port <= 65535
        ):
            return
        self._nodes[name] = DiscoveredNode(
            instance=name, addresses=addresses, port=int(info.port), role=role,
            protocol_version=properties["v"], window_id=window_id,
            content_port=content_port, node_id=node_id, name=node_name,
            pairing_open=pairing_open, created_at=born, leader_epoch=epoch,
        )
        on_update(self.nodes)


def choose_auto_role(
    *, local_node_id: str, local_created_at: int | float,
    discovered: tuple[DiscoveredNode, ...] | list[DiscoveredNode],
) -> str:
    """Choose an initial AUTO role without changing explicit peers.

    Existing explicit Masters win to avoid split-brain.  When several fresh
    AUTO installations start together, the oldest persistent installation wins;
    node_id is the deterministic tie breaker.  A network containing only Slaves
    needs a Master, so the AUTO node becomes it.
    """
    peers = [node for node in discovered if node.node_id and node.node_id != local_node_id]
    if any(node.role == "master" for node in peers):
        return "slave"
    auto_peers = [node for node in peers if node.role == "auto"]
    if auto_peers:
        local_key = (max(0, int(float(local_created_at or 0))), str(local_node_id))
        candidates = [local_key]
        candidates.extend((max(0, int(node.created_at or 0)), node.node_id) for node in auto_peers)
        return "master" if local_key == min(candidates) else "slave"
    return "master"


def scan_for_auto_election(
    *, addresses: list[str], port: int, node_id: str, name: str,
    created_at: int | float, duration_seconds: float = AUTO_ELECTION_SCAN_SECONDS,
) -> tuple[DiscoveredNode, ...]:
    """Perform a short discovery-only AUTO election scan.

    No identity, certificate, trust record or cluster registry is changed here.
    """
    advertiser = DiscoveryAdvertiser(addresses)
    browser = DiscoveryBrowser()
    latest: tuple[DiscoveredNode, ...] = ()
    lock = threading.Lock()

    def on_update(nodes):
        nonlocal latest
        with lock:
            latest = tuple(nodes)

    try:
        advertiser.start(
            port, role="auto", content_port=port, node_id=node_id, name=name,
            pairing_open=False, created_at=created_at, duration_seconds=None,
        )
        browser.start(on_update)
        time.sleep(max(0.1, float(duration_seconds)))
        with lock:
            return latest
    finally:
        browser.stop()
        advertiser.stop()
