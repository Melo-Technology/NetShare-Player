"""Authenticated leader probes used to resolve failover and returning Masters."""
from __future__ import annotations

import socket
import threading

from .protocol import receive_frame, send_frame
from .tls import accept_mutual_tls, connect_mutual_tls


class LeaderProbeListener:
    def __init__(
        self, *, host: str, port: int, identity, trust_store,
        node_id: str, epoch_getter, log=lambda _message, _kind="info": None,
    ):
        self.host = host
        self.port = int(port)
        self.identity = identity
        self.trust_store = trust_store
        self.node_id = node_id
        self.epoch_getter = epoch_getter
        self._log = log
        self._listener = None
        self._thread = None
        self._stop = threading.Event()

    def start(self) -> int:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(8)
        listener.settimeout(0.5)
        self._listener = listener
        self.port = int(listener.getsockname()[1])
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="netshare-cluster-leader-probe",
        )
        self._thread.start()
        return self.port

    def _serve(self):
        while not self._stop.is_set():
            try:
                secure, peer = accept_mutual_tls(
                    self._listener, self.identity, self.trust_store, log=self._log,
                )
            except (OSError, TimeoutError):
                continue
            try:
                secure.settimeout(5.0)
                request = receive_frame(secure)
                if str(request.get("op", "")).upper() != "LEADER_PROBE":
                    send_frame(secure, {"status": 400})
                else:
                    send_frame(secure, {
                        "status": 200, "leader_node_id": self.node_id,
                        "leader_epoch": int(self.epoch_getter()),
                        "peer_node_id": peer.node_id,
                    })
            except (ConnectionError, OSError, ValueError):
                pass
            finally:
                secure.close()

    def stop(self):
        self._stop.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)


def probe_leader(*, host: str, port: int, identity, trust_store, expected_node_id: str, log=lambda _m, _k="info": None) -> dict:
    secure = None
    try:
        secure, peer = connect_mutual_tls(
            (host, int(port)), identity, trust_store, timeout=5.0, log=log,
        )
        if peer.node_id != expected_node_id:
            raise PermissionError("leader probe identity mismatch")
        send_frame(secure, {"op": "LEADER_PROBE"})
        response = receive_frame(secure)
        if response.get("status") != 200 or response.get("leader_node_id") != expected_node_id:
            raise PermissionError("leader probe rejected")
        return response
    finally:
        if secure is not None:
            secure.close()
