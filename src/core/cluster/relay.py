"""Master-side exact-range ticket issuance and bounded streaming relay."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ByteRange
from .listing import ListingPage
from .protocol import (
    ClusterRemoteError,
    request_derived,
    request_file,
    request_listing,
    request_metadata,
)
from .tickets import TicketIssuer


@dataclass(frozen=True)
class RelayResponse:
    status: int
    headers: dict[str, str]
    length: int


def resolve_http_range(header: str | None, size: int) -> ByteRange | None:
    if not header:
        return None
    if not header.startswith("bytes=") or "," in header:
        raise ValueError("unsupported range")
    start_text, end_text = header[6:].strip().split("-", 1)
    if not start_text:
        suffix = int(end_text)
        if suffix <= 0:
            raise ValueError("invalid range")
        return ByteRange(max(0, size - suffix), size - 1)
    start = int(start_text)
    end = min(int(end_text) if end_text else size - 1, size - 1)
    return ByteRange(start, end)


class MasterRelay:
    def __init__(
        self, *, cluster_id: str, master_node_id: str,
        issuer: TicketIssuer, generation_for, connect_to,
        log=lambda _message, _kind="info": None,
    ):
        self.cluster_id = cluster_id
        self.master_node_id = master_node_id
        self.issuer = issuer
        self.generation_for = generation_for
        self.connect_to = connect_to
        self._log = log

    def relay(
        self, *, slave_node_id: str, device_id: str, path: str,
        method: str, range_header: str | None, writer,
        on_headers=lambda _response: None,
        allow_protected: bool = False,
    ) -> RelayResponse:
        metadata_connection = self.connect_to(slave_node_id)
        try:
            metadata = request_metadata(metadata_connection, path)
        finally:
            metadata_connection.close()
        byte_range = resolve_http_range(range_header, metadata.size)
        ticket = self.issuer.issue(
            cluster_id=self.cluster_id, issuer_node_id=self.master_node_id,
            audience_node_id=slave_node_id, device_id=device_id,
            method=method, path=path, byte_range=byte_range,
            allow_protected=bool(allow_protected and metadata.protected),
            audience_generation=self.generation_for(slave_node_id),
        )
        connection = self.connect_to(slave_node_id)
        try:
            response = request_file(
                connection, operation=method, path=path, byte_range=byte_range,
                device_id=device_id, ticket=ticket,
            )
            status = int(response.get("status", 500))
            if status not in (200, 206):
                if response.get("error"):
                    raise ClusterRemoteError(
                        str(response["error"]),
                        str(response.get("message") or "slave rejected relay"),
                    )
                raise ConnectionError("slave rejected relay")
            length = int(response["length"])
            headers = {
                "Content-Type": str(response["mime"]),
                "Content-Length": str(length),
                "Accept-Ranges": "bytes",
                "ETag": str(response["etag"]),
            }
            if response.get("content_range"):
                headers["Content-Range"] = str(response["content_range"])
            relay_response = RelayResponse(status, headers, length)
            on_headers(relay_response)
            if method == "GET":
                remaining = length
                while remaining:
                    chunk = connection.recv(min(256 * 1024, remaining))
                    if not chunk:
                        raise ConnectionError("slave relay interrupted")
                    writer.write(chunk)
                    remaining -= len(chunk)
            return relay_response
        finally:
            connection.close()

    def list_directory(
        self, *, slave_node_id: str, device_id: str,
        path: str, cursor: str, limit: int, allow_protected: bool = False,
    ) -> ListingPage:
        self._log(
            f"CLUSTER LIST ticket issue -> {slave_node_id} "
            f"[path={path!r} cursor={'set' if cursor else 'empty'} limit={limit}]",
            "info",
        )
        ticket = self.issuer.issue(
            cluster_id=self.cluster_id, issuer_node_id=self.master_node_id,
            audience_node_id=slave_node_id, device_id=device_id,
            method="LIST", path=path, byte_range=None,
            allow_protected=allow_protected,
            audience_generation=self.generation_for(slave_node_id),
            list_cursor=cursor, list_limit=limit,
        )
        self._log(
            f"CLUSTER LIST mTLS connect -> {slave_node_id} [path={path!r}]",
            "info",
        )
        connection = self.connect_to(slave_node_id)
        try:
            self._log(
                f"CLUSTER LIST request -> {slave_node_id} [path={path!r}]",
                "info",
            )
            page = request_listing(
                connection, path=path, cursor=cursor, limit=limit,
                device_id=device_id, ticket=ticket,
            )
            self._log(
                f"CLUSTER LIST success <- {slave_node_id} "
                f"[path={path!r} items={len(page.items)} "
                f"next_cursor={'set' if page.next_cursor else 'empty'}]",
                "ok",
            )
            return page
        finally:
            connection.close()

    def derived_resource(
        self, *, slave_node_id: str, device_id: str, path: str,
        operation: str, params: dict, allow_protected: bool = False,
    ) -> tuple[int, str, bytes]:
        metadata_connection = self.connect_to(slave_node_id)
        try:
            metadata = request_metadata(metadata_connection, path)
        finally:
            metadata_connection.close()
        ticket = self.issuer.issue(
            cluster_id=self.cluster_id, issuer_node_id=self.master_node_id,
            audience_node_id=slave_node_id, device_id=device_id,
            method=operation, path=path, byte_range=None,
            allow_protected=bool(allow_protected and metadata.protected),
            audience_generation=self.generation_for(slave_node_id),
            ttl_seconds=60, resource_params=params,
        )
        connection = self.connect_to(slave_node_id)
        try:
            response, body = request_derived(
                connection, operation=operation, path=path,
                device_id=device_id, params=params, ticket=ticket,
            )
            if response.get("error"):
                raise ClusterRemoteError(
                    str(response["error"]),
                    str(response.get("message") or "derived resource rejected"),
                )
            return (
                int(response.get("status", 500)),
                str(response.get("mime", "application/octet-stream")), body,
            )
        finally:
            connection.close()
