"""Player-facing read/navigation controller; pairing is desktop-to-desktop."""

from .registry import ClusterRegistry, MAX_SLAVES


class ClusterControlService:
    def __init__(
        self, registry: ClusterRegistry, remove_node=None, node_status=None,
        audit_log=None,
    ):
        self.registry = registry
        self._remove_node = remove_node or registry.remove
        self._node_status = node_status
        self._audit_log = audit_log

    def list_nodes(self) -> list[dict]:
        nodes = []
        for node in self.registry.nodes:
            status = (
                self._node_status(node.node_id) if self._node_status is not None
                else {"state": "reachable" if node.online else "unreachable",
                      "consecutive_failures": 0}
            )
            nodes.append({
                "id": node.node_id, "name": node.name, "online": node.online,
                **status,
            })
        return nodes

    def remove_node(self, node_id: str) -> bool:
        return self._remove_node(node_id)

    def list_events(self, limit: int = 200) -> list[dict]:
        if self._audit_log is None:
            return []
        return self._audit_log.list_events(limit)

    def capacity(self) -> dict:
        count = len(self.registry.nodes)
        return {
            "registered": count,
            "maximum": MAX_SLAVES,
            "available": MAX_SLAVES - count,
        }
