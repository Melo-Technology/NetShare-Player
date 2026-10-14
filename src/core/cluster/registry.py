"""Persistent bounded registry for one master and at most five slaves."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_SLAVES = 5


@dataclass(frozen=True)
class SlaveNode:
    node_id: str
    name: str
    host: str
    port: int
    certificate_serial: int
    online: bool = False
    created_at: int = 0


class ClusterRegistry:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._nodes: dict[str, SlaveNode] = {}
        self._load()

    @property
    def nodes(self) -> tuple[SlaveNode, ...]:
        with self._lock:
            return tuple(sorted(self._nodes.values(), key=lambda node: node.name.lower()))

    def add(self, node: SlaveNode) -> None:
        if not node.node_id or not node.name or not 1 <= node.port <= 65535:
            raise ValueError("invalid slave node")
        with self._lock:
            if node.node_id not in self._nodes and len(self._nodes) >= MAX_SLAVES:
                raise ValueError("maximum five slave nodes")
            self._nodes[node.node_id] = node
            self._save()

    def get(self, node_id: str) -> SlaveNode | None:
        with self._lock:
            return self._nodes.get(node_id)

    def remove(self, node_id: str) -> bool:
        with self._lock:
            removed = self._nodes.pop(node_id, None) is not None
            if removed:
                self._save()
            return removed

    def set_online(self, node_id: str, online: bool) -> bool:
        """Update volatile reachability without persisting a stale truth."""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return False
            self._nodes[node_id] = SlaveNode(
                node.node_id, node.name, node.host, node.port,
                node.certificate_serial, bool(online), node.created_at,
            )
            return True

    def update_endpoint(
        self, node_id: str, host: str, port: int, certificate_serial: int,
    ) -> bool:
        """Persist only a previously authorized peer's network endpoint."""
        clean_host = str(host).strip()
        if not clean_host or not 1 <= int(port) <= 65535:
            raise ValueError("invalid slave endpoint")
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return False
            if node.certificate_serial != int(certificate_serial):
                raise ValueError("cluster peer certificate serial mismatch")
            self._nodes[node_id] = SlaveNode(
                node.node_id, node.name, clean_host, int(port),
                node.certificate_serial, node.online, node.created_at,
            )
            self._save()
            return True

    def _load(self):
        if not self.path.exists():
            return
        value = json.loads(self.path.read_text(encoding="utf-8"))
        for item in value.get("nodes", []):
            node = SlaveNode(**{**item, "online": False})
            self._nodes[node.node_id] = node
        if len(self._nodes) > MAX_SLAVES:
            raise ValueError("cluster registry exceeds slave limit")

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({
            "nodes": [{**asdict(node), "online": False} for node in self.nodes],
        }, separators=(",", ":"), sort_keys=True), encoding="utf-8")
        os.replace(temporary, self.path)
