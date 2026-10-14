"""Chantier B2 cross-network E2E ciphertext relay routes."""
import json
import threading
import time
from urllib.parse import unquote

import src.state as state
from src.core.p2p_invitations import p2p_invitation_store
from src.core.p2p_relay import (
    CLEAR_CHUNK_SIZE,
    AES_GCM_ENVELOPE_OVERHEAD,
    MAX_METADATA_BYTES,
    P2PRelayError,
    P2PRelayStore,
)

_stores = {}
_stores_lock = threading.Lock()
_janitors = set()


def _store() -> P2PRelayStore:
    root = state.INBOX_DIR.parent / ".netshare-p2p-relay"
    key = str(root.resolve())
    with _stores_lock:
        store = _stores.setdefault(key, P2PRelayStore(root))
        if key not in _janitors:
            _janitors.add(key)
            thread = threading.Thread(
                target=_relay_janitor,
                args=(store,),
                name="netshare-p2p-relay-cleanup",
                daemon=True,
            )
            thread.start()
        return store


def _relay_janitor(store: P2PRelayStore) -> None:
    while True:
        time.sleep(300)
        try:
            store.cleanup()
        except Exception:
            # Cleanup is best-effort; request paths still enforce expiry.
            pass


def _cluster_replicate_file(relay_id: str, relative_path: str) -> None:
    manager = getattr(state, "_cluster_runtime", None)
    replicate = getattr(manager, "replicate_p2p_relay_write", None)
    if not callable(replicate):
        return
    path = _store().root / relay_id / relative_path
    try:
        payload = path.read_bytes()
    except OSError:
        return
    try:
        replicate(relay_id, relative_path, payload)
    except Exception:
        # Replication is durability hardening; the primary transfer must remain
        # available even when every Slave is temporarily offline. Heartbeat
        # resync will fill the gap when a node returns.
        pass


def _cluster_replicate_metadata(relay_id: str) -> None:
    _cluster_replicate_file(relay_id, "relay.json")


def _cluster_delete_relay(relay_id: str) -> None:
    manager = getattr(state, "_cluster_runtime", None)
    replicate = getattr(manager, "replicate_p2p_relay_delete", None)
    if callable(replicate):
        try:
            replicate(relay_id)
        except Exception:
            pass


class P2PRelayRoutesMixin:
    def _relay_owner(self) -> str:
        return self._device_id() or f"ip:{self.client_address[0]}"

    def _relay_token(self) -> str:
        return str(self.headers.get("X-P2P-Relay-Token", "")).strip()

    def _relay_error(self, error: P2PRelayError):
        self.send_error_json(str(error), error.status, code="p2p.relay_failed", domain="transfer", support_code="P2P-B2")

    def _route_p2p_relay_accept(self):
        body = self._read_body(MAX_METADATA_BYTES)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            invitation_id = str(payload.get("invitation_id", ""))
            acceptance = payload.get("acceptance")
            receiver_token = str(payload.get("receiver_token", "")).strip()
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            return self.send_error_json("Invalid relay acceptance", 400)
        invitation_token = str(self.headers.get("X-P2P-Invitation-Token", "")).strip()
        grant = p2p_invitation_store.inspect(invitation_token)
        try:
            store = _store()
            if grant is None or grant.invitation_id != invitation_id:
                # B3: the first accept may have committed server-side while its
                # 201 response was lost. The invitation is already consumed,
                # so recovery is allowed only with the exact same signed
                # acceptance and receiver-generated capability.
                result = store.retry_accept(
                    invitation_id=invitation_id, acceptance=acceptance,
                    receiver_token=receiver_token,
                )
                _cluster_replicate_metadata(result["relay_id"])
                return self.send_json(result, 201)
            result = store.accept(
                invitation=grant.envelope, acceptance=acceptance,
                receiver_token=receiver_token or None,
            )
            if result.get("idempotent") is not True:
                consumed = p2p_invitation_store.consume(invitation_token, invitation_id)
                if consumed is None:
                    store.discard(result["relay_id"])
                    _cluster_delete_relay(result["relay_id"])
                    return self.send_error_json("Invitation already consumed or expired", 410)
            _cluster_replicate_metadata(result["relay_id"])
            self.send_json(result, 201)
        except P2PRelayError as error:
            self._relay_error(error)

    def _route_p2p_relay_sender_status(self, invitation_id: str):
        try:
            self.send_json(_store().sender_status(invitation_id))
        except P2PRelayError as error:
            self._relay_error(error)

    def _route_p2p_relay_configure(self, invitation_id: str):
        body = self._read_body(MAX_METADATA_BYTES)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            result = _store().configure(
                invitation_id=invitation_id,
                owner=self._relay_owner(),
                descriptor=payload.get("descriptor"),
                items=payload.get("items"),
                ttl_seconds=int(payload.get("ttl_seconds", 24 * 60 * 60)),
            )
            _cluster_replicate_metadata(str(result.get("relay_id", "")))
            self.send_json(result)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            self.send_error_json("Invalid relay configuration", 400)
        except P2PRelayError as error:
            self._relay_error(error)

    def _route_p2p_relay_chunk_put(self, relay_id: str, item_id: str, chunk_index: str):
        try:
            index = int(chunk_index)
        except ValueError:
            return self.send_error_json("Invalid relay chunk index", 400)
        body = self._read_body(CLEAR_CHUNK_SIZE + AES_GCM_ENVELOPE_OVERHEAD, allow_empty=False)
        if body is None:
            return
        try:
            decoded_item_id = unquote(item_id)
            result = _store().put_chunk(
                relay_id=relay_id,
                item_id=decoded_item_id,
                chunk_index=index,
                data=body,
                owner=self._relay_owner(),
            )
            _cluster_replicate_file(
                relay_id, f"chunks/{decoded_item_id}/{index:08d}.bin",
            )
            _cluster_replicate_metadata(relay_id)
            self.send_json(result)
        except P2PRelayError as error:
            self._relay_error(error)

    def _route_p2p_relay_commit(self, relay_id: str):
        body = self._read_body(MAX_METADATA_BYTES)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            result = _store().commit(
                relay_id=relay_id,
                owner=self._relay_owner(),
                completion=payload.get("completion"),
            )
            _cluster_replicate_metadata(relay_id)
            self.send_json(result)
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            self.send_error_json("Invalid relay completion", 400)
        except P2PRelayError as error:
            self._relay_error(error)

    def _route_p2p_relay_receiver_status(self):
        try:
            self.send_json(_store().receiver_status(self._relay_token()))
        except P2PRelayError as error:
            self._relay_error(error)

    def _route_p2p_relay_chunk_get(self, relay_id: str, item_id: str, chunk_index: str):
        try:
            index = int(chunk_index)
            data = _store().read_chunk(
                token=self._relay_token(), relay_id=relay_id,
                item_id=unquote(item_id), chunk_index=index,
            )
        except ValueError:
            return self.send_error_json("Invalid relay chunk index", 400)
        except P2PRelayError as error:
            return self._relay_error(error)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _route_p2p_relay_download_complete(self):
        try:
            token = self._relay_token()
            status = _store().receiver_status(token)
            relay_id = str(status.get("relay_id", ""))
            _store().complete_download(token)
            if relay_id:
                _cluster_delete_relay(relay_id)
            self.send_json({"ok": True})
        except P2PRelayError as error:
            self._relay_error(error)

    def _route_p2p_relay_revoke(self, relay_id: str):
        try:
            if _store().revoke(relay_id=relay_id, owner=self._relay_owner()):
                _cluster_delete_relay(relay_id)
                return self.send_json({"ok": True})
            self.send_error_json("Relay session not found", 404)
        except P2PRelayError as error:
            self._relay_error(error)
