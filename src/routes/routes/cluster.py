"""Cluster federation routes.

Administrative cluster controls remain LAN-only and require a trusted Player.
Read-only content federation is also available to an authenticated NetShare Web
session through the Master.  The browser never talks to a Slave directly: the
Master keeps issuing the existing short-lived, exact-path cluster tickets and
relays them over the already-authenticated mTLS channel.
"""

import hashlib
from urllib.parse import parse_qs, urlparse

import src.state as state
from src.core.cluster.listing import MAX_DIRECTORY_ENTRIES
from src.core.cluster.protocol import ClusterRemoteError
from ..tunnel import _uses_public_access_policy


class ClusterRoutesMixin:
    _CLUSTER_PREFIX = "/@cluster/"
    _WEB_READER_PREFIX = "web-session:"
    _LAN_READER_PREFIX = "lan-reader:"

    def _parse_cluster_virtual_path(self, path: str):
        value = str(path or "")
        if not value.startswith(self._CLUSTER_PREFIX):
            return None
        remainder = value[len(self._CLUSTER_PREFIX):]
        node_id, separator, child = remainder.partition("/")
        if not node_id or not node_id.replace("-", "").replace("_", "").isalnum():
            return None
        return node_id, "/" + child if separator else "/"

    @classmethod
    def _cluster_web_reader_id(cls, session_id: str) -> str:
        """Return the bounded identity embedded in cluster tickets for Web.

        Cluster tickets are already bound to a device identity.  A browser
        session is not a trusted mobile device, so it receives its own stable,
        revocable identity instead of borrowing a device credential.
        """
        value = str(session_id or "").strip()
        if not value:
            return ""
        return f"{cls._WEB_READER_PREFIX}{value}"[:128]

    def _cluster_reader_id(self, *, web_session_id: str = "") -> str:
        """Resolve the authenticated read identity for cluster content.

        Trusted Players keep their real ``device_id`` so premium ownership and
        existing cluster semantics are unchanged.  A normal LAN Player that
        authenticated with the server password but has not paired for write
        access receives a synthetic, namespaced read identity.  This lets the
        ordinary file browser treat the cluster as one computer without
        allowing an untrusted client to impersonate a premium-enabled device.

        Public/tunnel traffic still requires a valid read-only Web session.
        Guest-profile sessions deliberately do not receive cluster federation:
        their per-folder allow-list applies only to the local server.
        """
        if web_session_id:
            if state.WEB_SESSION_STORE.is_active_id(str(web_session_id)):
                return self._cluster_web_reader_id(web_session_id)
            return ""

        if _uses_public_access_policy(self):
            lookup = self._web_session_lookup(touch=False)
            if lookup.status == "valid" and lookup.session is not None:
                return self._cluster_web_reader_id(lookup.session.id)
            return ""

        guest_check = getattr(self, "_has_guest_session", None)
        if callable(guest_check) and guest_check():
            return ""

        device_id = self._device_id()
        if device_id and self._has_device_credential(device_id):
            return device_id

        # The request has already passed the ordinary LAN authentication guard
        # before browse/cluster routes call this helper.  Never reuse an
        # untrusted caller-supplied device id directly: premium checks on the
        # Slave are keyed by device id.  A deterministic synthetic namespace
        # therefore preserves read-only access while remaining unable to match
        # any paired/premium identity.
        client = getattr(self, "client_address", ("", 0))
        client_host = str(client[0] if isinstance(client, tuple) and client else "")
        seed = f"{state.SERVER_ID}\0{client_host}\0{device_id}".encode("utf-8")
        return f"{self._LAN_READER_PREFIX}{hashlib.sha256(seed).hexdigest()[:32]}"

    def _cluster_content_context(
        self, *, web_session_id: str = "", emit_error: bool = True,
    ):
        """Return ``(controller, reader_id)`` for federated read operations."""
        controller = state._cluster_controller
        if not state.FEATURE_FLAGS.get("cluster") or controller is None:
            if emit_error:
                self.send_error_json("Cluster feature unavailable", 404)
            return None, ""
        if state._cluster_relay is None:
            if emit_error:
                self.send_error_json("Cluster relay unavailable", 503)
            return None, ""
        reader_id = self._cluster_reader_id(web_session_id=web_session_id)
        if not reader_id:
            if emit_error:
                message = (
                    "Authenticated web session required"
                    if _uses_public_access_policy(self) or web_session_id
                    else "Trusted device required"
                )
                self.send_error_json(message, 403)
            return None, ""
        return controller, reader_id

    @staticmethod
    def _cluster_node_available(controller, node_id: str) -> bool:
        return any(
            str(node.get("id", "")) == str(node_id)
            and node.get("online") is True
            for node in controller.list_nodes()
        )

    @staticmethod
    def _cluster_node_media_capabilities(controller, node_id: str) -> dict:
        for node in controller.list_nodes():
            if str(node.get("id", "")) == str(node_id):
                value = node.get("media_capabilities")
                return dict(value) if isinstance(value, dict) else {"known": False}
        return {"known": False}

    def _probe_cluster_virtual_file(
        self, node_id: str, path: str, *, web_session_id: str,
    ):
        """HEAD a remote file without writing an HTTP response.

        NetShare Web uses this to mint its own short-lived download/media
        grants while preserving the cluster ticket and premium checks on the
        Slave.  ``None`` deliberately collapses remote errors to an unavailable
        resource; the Web grant endpoints return their existing bounded error.
        """
        controller, reader_id = self._cluster_content_context(
            web_session_id=web_session_id, emit_error=False,
        )
        if controller is None or not self._cluster_node_available(controller, node_id):
            return None
        try:
            return state._cluster_relay.relay(
                slave_node_id=node_id, device_id=reader_id, path=path,
                method="HEAD", range_header=None, writer=None,
                allow_protected=True,
            )
        except (ClusterRemoteError, ConnectionError, OSError, ValueError, KeyError):
            return None

    def _cluster_virtual_roots(self) -> list[dict]:
        if state.effective_cluster_role() == "standalone":
            return []
        controller = state._cluster_controller
        if not state.FEATURE_FLAGS.get("cluster"):
            state._emit("CLUSTER virtual folders skipped: feature disabled", "info")
            return []
        if controller is None:
            state._emit("CLUSTER virtual folders skipped: controller unavailable", "error")
            return []
        reader_id = self._cluster_reader_id()
        if not reader_id:
            state._emit(
                "CLUSTER virtual folders skipped: no trusted Player or Web session",
                "info",
            )
            return []
        roots = []
        nodes = controller.list_nodes()
        if not nodes:
            state._emit("CLUSTER virtual folders: no registered Slave", "info")
        for node in nodes:
            if node.get("online") is not True:
                state._emit(
                    f"CLUSTER virtual folder absent: {node['name']} is offline",
                    "info",
                )
                continue
            state._emit(
                f"CLUSTER virtual folder injected: {node['name']}", "ok",
            )
            root = {
                "name": node["name"],
                "path": f"{self._CLUSTER_PREFIX}{node['id']}",
                "is_dir": True,
                "size": None,
                "modified": "",
                "cluster_node_id": node["id"],
            }
            if isinstance(node.get("media_capabilities"), dict):
                root["cluster_media_capabilities"] = dict(node["media_capabilities"])
            roots.append(root)
        return roots

    def _route_cluster_virtual_list(
        self, node_id: str, path: str, *,
        paginated: bool | None = None, offset: int = 0, limit: int = 100,
    ):
        # /list has two response contracts: legacy clients receive a bare
        # array, while newer mobile/web clients that send offset/limit receive
        # the standard pagination envelope.  The frozen browse route dispatches
        # cluster paths before it can forward those values, so recover the
        # already-validated query contract from the request URL here.  This
        # keeps local and federated directory responses schema-compatible.
        if paginated is None:
            query = parse_qs(urlparse(getattr(self, "path", "")).query)
            paginated = "limit" in query or "offset" in query
            if paginated:
                try:
                    limit = min(int(query.get("limit", ["100"])[0]), 200)
                    offset = max(int(query.get("offset", ["0"])[0]), 0)
                except (ValueError, TypeError, IndexError):
                    limit, offset = 100, 0
        controller, reader_id = self._cluster_content_context()
        if controller is None:
            return
        nodes = {node["id"]: node for node in controller.list_nodes()}
        if node_id not in nodes or nodes[node_id].get("online") is not True:
            return self.send_error_json("Cluster Slave unavailable", 503)
        items = []
        cursor = ""
        seen_cursors = set()
        try:
            while True:
                page = state._cluster_relay.list_directory(
                    slave_node_id=node_id, device_id=reader_id,
                    path=path, cursor=cursor, limit=100,
                    allow_protected=True,
                )
                for item in page.items:
                    mapped = dict(item)
                    mapped["path"] = f"{self._CLUSTER_PREFIX}{node_id}{item['path']}"
                    mapped.setdefault("modified", "")
                    items.append(mapped)
                    if len(items) > MAX_DIRECTORY_ENTRIES:
                        raise ValueError("cluster directory exceeds safety bound")
                cursor = page.next_cursor
                if not cursor:
                    break
                if cursor in seen_cursors:
                    raise ValueError("cluster listing cursor did not advance")
                seen_cursors.add(cursor)
            if paginated:
                total = len(items)
                page = items[offset:offset + limit]
                return self.send_json({
                    "items": page,
                    "offset": offset,
                    "limit": limit,
                    "total": total,
                    "has_more": offset + len(page) < total,
                })
            return self.send_json(items)
        except ClusterRemoteError as error:
            state._emit(
                f"CLUSTER virtual LIST rejected: node={node_id} path={path!r} "
                f"code={error.code} message={error}",
                "error",
            )
            return self.send_error_json(
                f"cluster_ticket_{error.code}", 403,
            )
        except (ConnectionError, OSError, ValueError, KeyError) as error:
            state._emit(
                f"CLUSTER virtual LIST failed: node={node_id} path={path!r} "
                f"{type(error).__name__}: {error}",
                "error",
            )
            return self.send_error_json("Cluster listing unavailable", 503)

    def _route_cluster_virtual_file(
        self, node_id: str, path: str, method="GET", *, web_session_id: str = "",
    ):
        return self._route_cluster_file(
            {"node_id": [node_id], "path": [path]}, method=method,
            web_session_id=web_session_id,
        )

    def _route_cluster_derived(
        self, node_id: str, path: str, operation: str, params: dict,
    ):
        controller, reader_id = self._cluster_content_context()
        if controller is None:
            return
        nodes = {node["id"]: node for node in controller.list_nodes()}
        if node_id not in nodes or nodes[node_id].get("online") is not True:
            return self.send_error_json("Cluster Slave unavailable", 503)
        capabilities = nodes[node_id].get("media_capabilities")
        capabilities = capabilities if isinstance(capabilities, dict) else {"known": False}
        required = None
        if operation in {"MEDIA_ANALYSIS", "WAVEFORM"}:
            required = "audio_analysis"
        elif operation == "THUMBNAIL":
            extension = str(path).rsplit(".", 1)[-1].lower() if "." in str(path) else ""
            if extension in {
                "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v",
                "mpg", "mpeg", "3gp", "ts", "mts", "m2ts", "vob", "ogv",
                "rm", "rmvb",
            }:
                required = "video_thumbnails"
        if capabilities.get("known") is True and required and capabilities.get(required) is not True:
            return self.send_json({
                "status": "unavailable",
                "error": "cluster_ffmpeg_unavailable",
                "capability": required,
                "fallback": "direct_play",
                "node_id": node_id,
                "message": "This cluster node cannot generate the requested derived media because FFmpeg capability is unavailable.",
            }, 501)
        try:
            status, mime, body = state._cluster_relay.derived_resource(
                slave_node_id=node_id, device_id=reader_id, path=path,
                operation=operation, params=params, allow_protected=True,
            )
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", len(body))
            self.send_header("Cache-Control", "private, max-age=86400" if status == 200 else "no-store")
            self._send_cors_headers()
            self.end_headers()
            if body:
                self.wfile.write(body)
        except ClusterRemoteError as error:
            return self.send_error_json(f"cluster_ticket_{error.code}", 403)
        except (ConnectionError, OSError, ValueError, KeyError) as error:
            state._emit(
                f"CLUSTER {operation} failed: node={node_id} path={path!r} "
                f"{type(error).__name__}: {error}", "error",
            )
            return self.send_error_json("Cluster derived resource unavailable", 503)

    def _cluster_guard(self, write: bool = False):
        if not state.FEATURE_FLAGS.get("cluster") or state._cluster_controller is None:
            self.send_error_json("Cluster feature unavailable", 404)
            return None
        if _uses_public_access_policy(self):
            self.send_error_json("Local network only", 403)
            return None
        if write and not self._has_device_credential():
            self.send_error_json("Trusted device required", 403)
            return None
        return state._cluster_controller

    def _route_cluster_nodes(self):
        controller = self._cluster_guard()
        if controller is not None:
            payload = {"nodes": controller.list_nodes()}
            if hasattr(controller, "capacity"):
                payload["capacity"] = controller.capacity()
            self.send_json(payload)

    def _route_cluster_events(self):
        controller = self._cluster_guard(write=True)
        if controller is not None:
            self.send_json({"events": controller.list_events()})

    def _route_cluster_file(self, params, method="GET", *, web_session_id: str = ""):
        controller, reader_id = self._cluster_content_context(
            web_session_id=web_session_id,
        )
        if controller is None:
            return
        node_id = str(params.get("node_id", [""])[0])
        path = str(params.get("path", [""])[0])
        if not node_id or not path or not reader_id:
            return self.send_error_json("Missing relay parameters", 400)
        if not self._cluster_node_available(controller, node_id):
            return self.send_error_json("Cluster Slave unavailable", 503)

        headers_sent = False

        def send_headers(response):
            nonlocal headers_sent
            self.send_response(response.status)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self._send_cors_headers()
            self.end_headers()
            headers_sent = True

        try:
            state._cluster_relay.relay(
                slave_node_id=node_id, device_id=reader_id, path=path,
                method=method, range_header=self.headers.get("Range"),
                writer=self.wfile, on_headers=send_headers,
                allow_protected=True,
            )
        except ClusterRemoteError as error:
            return self.send_error_json(f"cluster_ticket_{error.code}", 403)
        except (ConnectionError, OSError, ValueError):
            if not headers_sent:
                self.send_error_json("Cluster relay unavailable", 503)

    def _route_cluster_list(self, params):
        controller = self._cluster_guard()
        if controller is None:
            return
        if state._cluster_relay is None:
            return self.send_error_json("Cluster relay unavailable", 503)
        reader_id = self._cluster_reader_id()
        if not reader_id:
            return self.send_error_json("Authenticated LAN Player required", 403)
        node_id = str(params.get("node_id", [""])[0])
        path = str(params.get("path", [""])[0])
        cursor = str(params.get("cursor", [""])[0])
        device_id = reader_id
        try:
            limit = int(params.get("limit", ["50"])[0])
        except (TypeError, ValueError):
            return self.send_error_json("Invalid listing limit", 400)
        if not node_id or not path or not device_id:
            return self.send_error_json("Missing listing parameters", 400)
        try:
            page = state._cluster_relay.list_directory(
                slave_node_id=node_id, device_id=device_id, path=path,
                cursor=cursor, limit=limit, allow_protected=True,
            )
        except ClusterRemoteError as error:
            return self.send_error_json(f"cluster_ticket_{error.code}", 403)
        except (ConnectionError, OSError, ValueError):
            return self.send_error_json("Cluster listing unavailable", 503)
        self.send_json({"items": list(page.items), "next_cursor": page.next_cursor})

    def _route_cluster_node_delete(self, node_id: str):
        controller = self._cluster_guard(write=True)
        if controller is not None:
            node = next(
                (
                    item
                    for item in controller.list_nodes()
                    if str(item.get("id", "")) == node_id
                ),
                None,
            )
            removed = controller.remove_node(node_id)
            if removed and state._ws_manager is not None:
                state._ws_manager.notify_cluster_node_status(
                    node_id,
                    str(node.get("name", node_id)) if node is not None else node_id,
                    False,
                    removed=True,
                )
            self.send_json({"removed": removed})
