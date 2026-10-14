"""Single-request framed protocol for exact file access over mTLS."""

from __future__ import annotations

import json
import mimetypes
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from .models import ByteRange
from .listing import ListingCursorCodec, ListingPage, list_directory_page
from .tickets import TicketVerifier
from src.core.content_policy import resolve_visible_shared_path
from src.core.derived_media import DerivedMediaService
from src.core.shared_paths import parse_shared_path
from src.core.shared_roots import SharedRoot

MAX_FRAME_BYTES = 16 * 1024
STREAM_CHUNK_BYTES = 256 * 1024
DERIVED_OPERATIONS = {"ART", "MEDIA_ANALYSIS", "THUMBNAIL", "WAVEFORM", "LYRICS"}
ALLOWED_OPERATIONS = {
    "STAT", "GET", "HEAD", "LIST", "PING", "UNPAIR",
    "P2P_RELAY_WRITE", "P2P_RELAY_DELETE", "P2P_RELAY_PRUNE",
    *DERIVED_OPERATIONS,
}
MAX_DERIVED_RESPONSE_BYTES = 8 * 1024 * 1024


class ClusterProtocolError(ValueError):
    pass


class ClusterRemoteError(ClusterProtocolError):
    def __init__(self, code: str, message: str = ""):
        self.code = str(code)
        super().__init__(message or self.code)


def _read_exact(connection, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("cluster connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def _root_path_for_slot(roots: tuple[SharedRoot, ...], slot: str) -> Path | None:
    for root in roots:
        if root.slot == slot:
            return root.path
    return None



def send_frame(connection, payload: dict) -> None:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_FRAME_BYTES:
        raise ClusterProtocolError("cluster frame is too large")
    connection.sendall(struct.pack(">I", len(encoded)) + encoded)


def receive_frame(connection) -> dict:
    length = struct.unpack(">I", _read_exact(connection, 4))[0]
    if length < 2 or length > MAX_FRAME_BYTES:
        raise ClusterProtocolError("invalid cluster frame length")
    try:
        value = json.loads(_read_exact(connection, length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ClusterProtocolError("invalid cluster frame") from error
    if not isinstance(value, dict):
        raise ClusterProtocolError("invalid cluster frame")
    return value


def resolve_shared_path(roots: tuple[SharedRoot, ...], requested: str) -> tuple[str, Path]:
    if not isinstance(requested, str) or not requested.startswith("/"):
        raise ClusterProtocolError("invalid file path")
    parsed = parse_shared_path(requested)
    if parsed is None:
        raise ClusterProtocolError("invalid file path")
    slot, relative = parsed
    root_path = _root_path_for_slot(roots, slot)
    if root_path is None:
        raise ClusterProtocolError("file path escapes shared root")
    target = resolve_visible_shared_path(root_path, relative, require_file=True, slot=slot)
    if target is None:
        raise ClusterProtocolError("file path escapes shared root")
    return slot, target


def resolve_shared_directory(roots: tuple[SharedRoot, ...], requested: str) -> tuple[str, Path]:
    if not isinstance(requested, str) or not requested.startswith("/"):
        raise ClusterProtocolError("invalid directory path")
    parsed = parse_shared_path(requested)
    if parsed is None:
        raise ClusterProtocolError("invalid directory path")
    slot, relative = parsed
    root_path = _root_path_for_slot(roots, slot)
    if root_path is None:
        raise ClusterProtocolError("directory path escapes shared root")
    target = resolve_visible_shared_path(root_path, relative, slot=slot)
    if target is None:
        raise ClusterProtocolError("directory path escapes shared root")
    if not target.is_dir():
        raise FileNotFoundError(requested)
    return slot, target


def concrete_range(value, size: int) -> ByteRange | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ClusterProtocolError("invalid byte range")
    byte_range = ByteRange.from_dict(value)
    if byte_range.end >= size:
        raise ClusterProtocolError("unsatisfiable byte range")
    return byte_range


@dataclass(frozen=True)
class FileMetadata:
    size: int
    mime: str
    etag: str
    protected: bool


class SlaveFileProtocol:
    def __init__(
        self, *, roots: tuple[SharedRoot, ...], node_id: str, verifier: TicketVerifier,
        protected_check=lambda _path: False,
        access_check=lambda _path, _device_id: True,
        cursor_codec: ListingCursorCodec | None = None,
        unpair_callback=None,
        heartbeat_callback=None,
        derived_service: DerivedMediaService | None = None,
        relay_replica_write=None, relay_replica_delete=None,
        relay_replica_prune=None,
    ):
        self.roots = roots
        self.node_id = node_id
        self.verifier = verifier
        self.protected_check = protected_check
        self.access_check = access_check
        self.cursor_codec = cursor_codec
        self.unpair_callback = unpair_callback
        self.heartbeat_callback = heartbeat_callback
        self.derived_service = derived_service
        self.relay_replica_write = relay_replica_write
        self.relay_replica_delete = relay_replica_delete
        self.relay_replica_prune = relay_replica_prune

    def handle_once(self, connection, authenticated_peer_id: str) -> None:
        request = receive_frame(connection)
        operation = str(request.get("op", "")).upper()
        if operation not in ALLOWED_OPERATIONS or authenticated_peer_id != self.verifier.issuer_node_id:
            raise ClusterProtocolError("operation is not authorized")
        if operation == "UNPAIR":
            if self.unpair_callback is None:
                raise ClusterProtocolError("unpair is unavailable")
            self.unpair_callback()
            send_frame(connection, {"status": 200, "cleanup": "confirmed"})
            return
        if operation == "P2P_RELAY_WRITE":
            if self.relay_replica_write is None:
                raise ClusterProtocolError("relay replication is unavailable")
            relay_id = str(request.get("relay_id", ""))
            relative_path = str(request.get("relative_path", ""))
            length = int(request.get("length", -1))
            if length < 0 or length > 4 * 1024 * 1024 + 256 * 1024:
                raise ClusterProtocolError("invalid relay replica length")
            payload = _read_exact(connection, length) if length else b""
            self.relay_replica_write(relay_id, relative_path, payload)
            send_frame(connection, {"status": 200})
            return
        if operation == "P2P_RELAY_DELETE":
            if self.relay_replica_delete is None:
                raise ClusterProtocolError("relay replication is unavailable")
            self.relay_replica_delete(str(request.get("relay_id", "")))
            send_frame(connection, {"status": 200})
            return
        if operation == "P2P_RELAY_PRUNE":
            if self.relay_replica_prune is None:
                raise ClusterProtocolError("relay replication is unavailable")
            active = request.get("active_relay_ids")
            if not isinstance(active, list) or len(active) > 64:
                raise ClusterProtocolError("invalid relay replica inventory")
            self.relay_replica_prune([str(value) for value in active])
            send_frame(connection, {"status": 200})
            return
        if operation == "PING":
            nonce = str(request.get("nonce", ""))
            if not nonce or len(nonce) > 64:
                raise ClusterProtocolError("invalid heartbeat nonce")
            extra = {}
            if self.heartbeat_callback is not None:
                value = self.heartbeat_callback(request, authenticated_peer_id)
                if isinstance(value, dict):
                    extra = dict(value)
            send_frame(connection, {"status": 200, "nonce": nonce, **extra})
            return
        path = str(request.get("path", ""))
        if operation == "LIST":
            return self._handle_list(connection, request, path)
        _slot, target = resolve_shared_path(self.roots, path)
        stat = target.stat()
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        protected = bool(self.protected_check(path))
        etag = f'"{stat.st_size:x}-{stat.st_mtime_ns:x}"'
        if operation == "STAT":
            return send_frame(connection, {
                "status": 200, "size": stat.st_size, "mime": mime,
                "etag": etag, "protected": protected,
            })

        if operation in DERIVED_OPERATIONS:
            return self._handle_derived(
                connection, request, operation, path, target, protected,
            )

        requested_range = concrete_range(request.get("range"), stat.st_size)
        device_id = str(request.get("device_id", ""))
        if protected and not self.access_check(path, device_id):
            raise PermissionError("premium path is locked for this device")
        self.verifier.verify_and_consume(
            str(request.get("ticket", "")), audience_node_id=self.node_id,
            device_id=device_id, method=operation, path=path,
            byte_range=requested_range, requires_protected_access=protected,
        )
        start = requested_range.start if requested_range else 0
        end = requested_range.end if requested_range else stat.st_size - 1
        length = end - start + 1
        send_frame(connection, {
            "status": 206 if requested_range else 200,
            "size": stat.st_size, "length": length, "mime": mime,
            "etag": etag,
            "content_range": f"bytes {start}-{end}/{stat.st_size}" if requested_range else None,
        })
        if operation == "HEAD":
            return
        with target.open("rb") as stream:
            stream.seek(start)
            remaining = length
            while remaining:
                chunk = stream.read(min(STREAM_CHUNK_BYTES, remaining))
                if not chunk:
                    raise ConnectionError("file changed during relay")
                connection.sendall(chunk)
                remaining -= len(chunk)

    def _handle_derived(
        self, connection, request: dict, operation: str,
        path: str, target: Path, protected: bool,
    ) -> None:
        if self.derived_service is None:
            raise ClusterProtocolError("derived media service is unavailable")
        if request.get("range") is not None:
            raise ClusterProtocolError("Range is forbidden for derived resources")
        device_id = str(request.get("device_id", ""))
        if protected and not self.access_check(path, device_id):
            raise PermissionError("premium path is locked for this device")
        params = dict(request.get("params") or {})
        self.verifier.verify_and_consume(
            str(request.get("ticket", "")), audience_node_id=self.node_id,
            device_id=device_id, method=operation, path=path,
            byte_range=None, requires_protected_access=protected,
            resource_params=params,
        )
        if operation == "ART":
            resource = self.derived_service.artwork(target)
        elif operation == "MEDIA_ANALYSIS":
            resource = self.derived_service.media_analysis(path, target)
        elif operation == "THUMBNAIL":
            resource = self.derived_service.thumbnail(
                target, int(params["width"]), int(params["height"]),
            )
        elif operation == "WAVEFORM":
            resource = self.derived_service.waveform(
                path, target, int(params["samples"]),
            )
        else:  # LYRICS
            resource = self.derived_service.lyrics(path, target)
        if len(resource.body) > MAX_DERIVED_RESPONSE_BYTES:
            raise ClusterProtocolError("derived response exceeds protocol bound")
        send_frame(connection, {
            "status": resource.status, "mime": resource.mime,
            "length": len(resource.body),
        })
        if resource.body:
            connection.sendall(resource.body)

    def _handle_list(self, connection, request: dict, path: str) -> None:
        if self.cursor_codec is None:
            raise ClusterProtocolError("directory listing is unavailable")
        if path == "/":
            directory_roots = tuple(
                (root.slot, root.path, root.path) for root in self.roots
            )
        else:
            slot, directory = resolve_shared_directory(self.roots, path)
            root_path = _root_path_for_slot(self.roots, slot)
            directory_roots = ((slot, root_path, directory),)
        cursor = str(request.get("cursor") or "")
        limit = int(request.get("limit") or 0)
        device_id = str(request.get("device_id", ""))
        protected = bool(self.protected_check(path))
        if protected and not self.access_check(path, device_id):
            raise PermissionError("premium path is locked for this device")
        self.verifier.verify_and_consume(
            str(request.get("ticket", "")), audience_node_id=self.node_id,
            device_id=device_id, method="LIST", path=path, byte_range=None,
            requires_protected_access=protected,
            list_cursor=cursor, list_limit=limit,
        )
        page = list_directory_page(
            roots=directory_roots, path=path,
            limit=limit, cursor=cursor, codec=self.cursor_codec,
            device_id=device_id,
        )
        self._send_listing_page(connection, page)

    @staticmethod
    def _send_listing_page(connection, page: ListingPage) -> None:
        chunks = [page.items[index:index + 20] for index in range(0, len(page.items), 20)]
        if not chunks:
            chunks = [()]
        for index, items in enumerate(chunks):
            final = index == len(chunks) - 1
            send_frame(connection, {
                "status": 200,
                "items": list(items),
                "more": not final,
                "next_cursor": page.next_cursor if final else "",
            })


def request_metadata(connection, path: str) -> FileMetadata:
    send_frame(connection, {"op": "STAT", "path": path})
    response = receive_frame(connection)
    if response.get("status") != 200:
        raise ClusterProtocolError("slave metadata request failed")
    return FileMetadata(
        size=int(response["size"]), mime=str(response["mime"]),
        etag=str(response["etag"]), protected=response.get("protected") is True,
    )


def request_file(
    connection, *, operation: str, path: str, byte_range: ByteRange | None,
    device_id: str, ticket: str,
) -> dict:
    send_frame(connection, {
        "op": operation, "path": path,
        "range": byte_range.to_dict() if byte_range else None,
        "device_id": device_id, "ticket": ticket,
    })
    return receive_frame(connection)


def request_derived(
    connection, *, operation: str, path: str, device_id: str,
    params: dict, ticket: str,
) -> tuple[dict, bytes]:
    if operation not in DERIVED_OPERATIONS:
        raise ClusterProtocolError("invalid derived operation")
    send_frame(connection, {
        "op": operation, "path": path, "range": None,
        "device_id": device_id, "params": params, "ticket": ticket,
    })
    response = receive_frame(connection)
    length = int(response.get("length", 0))
    if length < 0 or length > MAX_DERIVED_RESPONSE_BYTES:
        raise ClusterProtocolError("invalid derived response length")
    return response, _read_exact(connection, length) if length else b""


def request_listing(
    connection, *, path: str, cursor: str, limit: int,
    device_id: str, ticket: str,
) -> ListingPage:
    send_frame(connection, {
        "op": "LIST", "path": path, "cursor": cursor, "limit": int(limit),
        "device_id": device_id, "ticket": ticket,
    })
    items = []
    next_cursor = ""
    while True:
        response = receive_frame(connection)
        if response.get("status") != 200:
            raise ClusterRemoteError(
                str(response.get("error") or "slave_error"),
                str(response.get("message") or "slave listing request failed"),
            )
        if not isinstance(response.get("items"), list):
            raise ClusterProtocolError("slave listing request failed")
        items.extend(item for item in response["items"] if isinstance(item, dict))
        if len(items) > 100:
            raise ClusterProtocolError("slave listing exceeded page bound")
        if response.get("more") is not True:
            next_cursor = str(response.get("next_cursor") or "")
            break
    return ListingPage(tuple(items), next_cursor)


def request_relay_replica_write(
    connection, *, relay_id: str, relative_path: str, payload: bytes,
) -> None:
    send_frame(connection, {
        "op": "P2P_RELAY_WRITE", "relay_id": relay_id,
        "relative_path": relative_path, "length": len(payload),
    })
    if payload:
        connection.sendall(payload)
    response = receive_frame(connection)
    if response.get("status") != 200:
        raise ClusterProtocolError("relay replica write failed")


def request_relay_replica_delete(connection, *, relay_id: str) -> None:
    send_frame(connection, {"op": "P2P_RELAY_DELETE", "relay_id": relay_id})
    response = receive_frame(connection)
    if response.get("status") != 200:
        raise ClusterProtocolError("relay replica delete failed")


def request_relay_replica_prune(connection, *, active_relay_ids: list[str]) -> None:
    send_frame(connection, {
        "op": "P2P_RELAY_PRUNE", "active_relay_ids": list(active_relay_ids),
    })
    response = receive_frame(connection)
    if response.get("status") != 200:
        raise ClusterProtocolError("relay replica prune failed")
