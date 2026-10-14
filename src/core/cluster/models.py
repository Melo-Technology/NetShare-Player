"""Typed, transport-independent cluster security models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ClusterRole(str, Enum):
    STANDALONE = "standalone"
    AUTO = "auto"
    MASTER = "master"
    SLAVE = "slave"


@dataclass(frozen=True)
class ByteRange:
    start: int
    end: int

    def __post_init__(self):
        if self.start < 0 or self.end < self.start:
            raise ValueError("invalid byte range")

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end}

    @classmethod
    def from_dict(cls, value: dict | None) -> ByteRange | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("invalid byte range")
        return cls(start=int(value["start"]), end=int(value["end"]))


@dataclass(frozen=True)
class TicketClaims:
    ticket_id: str
    cluster_id: str
    issuer_node_id: str
    audience_node_id: str
    device_id: str
    method: str
    path: str
    byte_range: ByteRange | None
    allow_protected: bool
    issued_at: int
    not_before: int
    expires_at: int
    audience_generation: int
    list_cursor: str = ""
    list_limit: int = 0
    resource_params: dict = field(default_factory=dict)
    protocol_version: int = 1

    def to_dict(self) -> dict:
        return {
            "v": self.protocol_version,
            "jti": self.ticket_id,
            "cluster": self.cluster_id,
            "iss": self.issuer_node_id,
            "aud": self.audience_node_id,
            "sub": self.device_id,
            "method": self.method,
            "path": self.path,
            "range": self.byte_range.to_dict() if self.byte_range else None,
            "protected": self.allow_protected,
            "iat": self.issued_at,
            "nbf": self.not_before,
            "exp": self.expires_at,
            "generation": self.audience_generation,
            "cursor": self.list_cursor,
            "limit": self.list_limit,
            "params": self.resource_params or {},
        }

    @classmethod
    def from_dict(cls, value: dict) -> TicketClaims:
        if not isinstance(value, dict):
            raise ValueError("invalid ticket claims")
        return cls(
            protocol_version=int(value["v"]), ticket_id=str(value["jti"]),
            cluster_id=str(value["cluster"]), issuer_node_id=str(value["iss"]),
            audience_node_id=str(value["aud"]), device_id=str(value["sub"]),
            method=str(value["method"]), path=str(value["path"]),
            byte_range=ByteRange.from_dict(value.get("range")),
            allow_protected=value.get("protected") is True,
            issued_at=int(value["iat"]), not_before=int(value["nbf"]),
            expires_at=int(value["exp"]),
            audience_generation=int(value["generation"]),
            list_cursor=str(value.get("cursor") or ""),
            list_limit=int(value.get("limit") or 0),
            resource_params=dict(value.get("params") or {}),
        )
