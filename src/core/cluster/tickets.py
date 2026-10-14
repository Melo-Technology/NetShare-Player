"""Compact Ed25519 cluster stream tickets with exact request binding."""

from __future__ import annotations

import base64
import json
import posixpath
import secrets
import time
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import ByteRange, TicketClaims
from .revocation import RevocationCapacityError, RevocationRegistry

DEFAULT_TTL_SECONDS = 60
MAX_TTL_SECONDS = 120
CLOCK_SKEW_SECONDS = 5
MAX_BATCH_SIZE = 4
MAX_TOKEN_BYTES = 8192


def normalize_resource_params(method: str, value: dict | None) -> dict:
    params = dict(value or {})
    if method == "THUMBNAIL":
        if set(params) != {"width", "height"} or not all(
            1 <= int(params[key]) <= 600 for key in ("width", "height")
        ):
            raise ValueError("invalid THUMBNAIL parameters")
        return {"height": int(params["height"]), "width": int(params["width"])}
    if method == "WAVEFORM":
        if set(params) != {"samples"} or not 32 <= int(params["samples"]) <= 4096:
            raise ValueError("invalid WAVEFORM parameters")
        return {"samples": int(params["samples"])}
    if params:
        raise ValueError("operation does not accept resource parameters")
    return {}


class TicketErrorCode(str, Enum):
    MALFORMED = "malformed"
    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    WRONG_AUDIENCE = "wrong_audience"
    WRONG_DEVICE = "wrong_device"
    WRONG_REQUEST = "wrong_request"
    REVOKED = "revoked"
    REPLAYED = "replayed"
    UNSUPPORTED_VERSION = "unsupported_version"
    CACHE_FULL = "cache_full"


class TicketValidationError(ValueError):
    def __init__(self, code: TicketErrorCode):
        self.code = code
        super().__init__(code.value)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


def normalize_ticket_path(path: str, *, allow_root: bool = False) -> str:
    value = str(path)
    if not value.startswith("/") or "\x00" in value or "\\" in value:
        raise ValueError("invalid ticket path")
    normalized = posixpath.normpath(value)
    if (
        normalized != value
        or (normalized == "/" and not allow_root)
        or ".." in value.split("/")
    ):
        raise ValueError("invalid ticket path")
    return value


class TicketIssuer:
    def __init__(
        self, private_key: bytes, clock=time.time,
        log=lambda _message, _kind="info": None,
    ):
        self._key = Ed25519PrivateKey.from_private_bytes(private_key)
        self.clock = clock
        self._log = log

    def issue(
        self,
        *,
        cluster_id: str,
        issuer_node_id: str,
        audience_node_id: str,
        device_id: str,
        method: str,
        path: str,
        byte_range: ByteRange | None,
        allow_protected: bool,
        audience_generation: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        list_cursor: str = "",
        list_limit: int = 0,
        resource_params: dict | None = None,
    ) -> str:
        ttl = int(ttl_seconds)
        if ttl < 1 or ttl > MAX_TTL_SECONDS:
            raise ValueError("invalid ticket TTL")
        normalized_method = method.upper()
        derived_methods = {"ART", "MEDIA_ANALYSIS", "THUMBNAIL", "WAVEFORM", "LYRICS"}
        if normalized_method not in ("GET", "HEAD", "LIST", *derived_methods):
            raise ValueError("invalid ticket method")
        if normalized_method == "LIST":
            if (
                byte_range is not None
                or not 1 <= int(list_limit) <= 100
                or len(str(list_cursor)) > 4096
            ):
                raise ValueError("invalid LIST pagination")
        elif normalized_method in derived_methods and byte_range is not None:
            raise ValueError("Range is forbidden for derived resources")
        elif list_cursor or list_limit:
            raise ValueError("file ticket cannot contain LIST pagination")
        params = normalize_resource_params(normalized_method, resource_params)
        identifiers = (cluster_id, issuer_node_id, audience_node_id, device_id)
        if any(not str(value).strip() or len(str(value)) > 128 for value in identifiers):
            raise ValueError("invalid ticket identity")
        now = int(self.clock())
        claims = TicketClaims(
            ticket_id=secrets.token_urlsafe(18),
            cluster_id=str(cluster_id),
            issuer_node_id=str(issuer_node_id),
            audience_node_id=str(audience_node_id),
            device_id=str(device_id),
            method=normalized_method,
            path=normalize_ticket_path(path, allow_root=normalized_method == "LIST"),
            byte_range=byte_range,
            allow_protected=bool(allow_protected),
            issued_at=now,
            not_before=now,
            expires_at=now + ttl,
            audience_generation=max(0, int(audience_generation)),
            list_cursor=str(list_cursor), list_limit=int(list_limit),
            resource_params=params,
        )
        payload = json.dumps(
            claims.to_dict(), separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
        self._log(
            f"CLUSTER ticket issued: id={claims.ticket_id} "
            f"method={claims.method} audience={claims.audience_node_id} "
            f"generation={claims.audience_generation}",
            "info",
        )
        return f"nst1.{_b64encode(payload)}.{_b64encode(self._key.sign(payload))}"

    def issue_batch(self, requests: list[dict]) -> list[str]:
        if not 1 <= len(requests) <= MAX_BATCH_SIZE:
            raise ValueError("invalid ticket batch size")
        return [self.issue(**request) for request in requests]


class TicketVerifier:
    def __init__(
        self,
        public_key: bytes,
        revocations: RevocationRegistry,
        *,
        cluster_id: str,
        issuer_node_id: str,
        clock=time.time,
        log=lambda _message, _kind="info": None,
    ):
        self._key = Ed25519PublicKey.from_public_bytes(public_key)
        self.revocations = revocations
        self.cluster_id = cluster_id
        self.issuer_node_id = issuer_node_id
        self.clock = clock
        self._log = log


    def set_issuer_node_id(self, node_id: str) -> None:
        value = str(node_id).strip()
        if not value or len(value) > 128:
            raise ValueError("invalid ticket issuer")
        self.issuer_node_id = value

    def verify_and_consume(
        self,
        token: str,
        *,
        audience_node_id: str,
        device_id: str,
        method: str,
        path: str,
        byte_range: ByteRange | None,
        requires_protected_access: bool = False,
        list_cursor: str = "",
        list_limit: int = 0,
        resource_params: dict | None = None,
    ) -> TicketClaims:
        claims = self._verify_signature(token)
        now = int(self.clock())
        if claims.protocol_version != 1:
            raise TicketValidationError(TicketErrorCode.UNSUPPORTED_VERSION)
        try:
            claim_params = normalize_resource_params(claims.method, claims.resource_params)
            request_params = normalize_resource_params(method.upper(), resource_params)
        except (TypeError, ValueError, KeyError) as error:
            raise TicketValidationError(TicketErrorCode.WRONG_REQUEST) from error
        if (
            claims.not_before < claims.issued_at
            or claims.expires_at <= claims.not_before
            or claims.expires_at - claims.issued_at > MAX_TTL_SECONDS
        ):
            raise TicketValidationError(TicketErrorCode.MALFORMED)
        if now + CLOCK_SKEW_SECONDS < claims.not_before:
            raise TicketValidationError(TicketErrorCode.NOT_YET_VALID)
        if now - CLOCK_SKEW_SECONDS > claims.expires_at:
            raise TicketValidationError(TicketErrorCode.EXPIRED)
        if claims.audience_node_id != audience_node_id:
            raise TicketValidationError(TicketErrorCode.WRONG_AUDIENCE)
        if (
            claims.cluster_id != self.cluster_id
            or claims.issuer_node_id != self.issuer_node_id
        ):
            raise TicketValidationError(TicketErrorCode.INVALID_SIGNATURE)
        if claims.device_id != device_id:
            raise TicketValidationError(TicketErrorCode.WRONG_DEVICE)
        try:
            requested_path = normalize_ticket_path(
                path, allow_root=method.upper() == "LIST",
            )
        except ValueError as error:
            raise TicketValidationError(TicketErrorCode.WRONG_REQUEST) from error
        if (
            claims.method != method.upper()
            or claims.path != requested_path
            or claims.byte_range != byte_range
            or claims.list_cursor != str(list_cursor)
            or claims.list_limit != int(list_limit)
            or claim_params != request_params
            or (requires_protected_access and not claims.allow_protected)
        ):
            raise TicketValidationError(TicketErrorCode.WRONG_REQUEST)
        if claims.method in {"ART", "MEDIA_ANALYSIS", "THUMBNAIL", "WAVEFORM", "LYRICS"}:
            if claims.expires_at - claims.issued_at != DEFAULT_TTL_SECONDS:
                raise TicketValidationError(TicketErrorCode.MALFORMED)
            if claims.byte_range is not None:
                raise TicketValidationError(TicketErrorCode.WRONG_REQUEST)
        current_generation = self.revocations.current_generation(audience_node_id)
        self._log(
            f"CLUSTER ticket verify: id={claims.ticket_id} method={claims.method} "
            f"ticket_generation={claims.audience_generation} "
            f"local_generation={current_generation}",
            "info",
        )
        if claims.audience_generation > current_generation:
            self.revocations.synchronize_generation(
                audience_node_id, claims.audience_generation,
            )
            self._log(
                f"CLUSTER ticket generation synchronized: "
                f"audience={audience_node_id} generation={claims.audience_generation}",
                "info",
            )
            current_generation = claims.audience_generation
        if claims.audience_generation < current_generation:
            self._log(
                f"CLUSTER ticket rejected: id={claims.ticket_id} reason=revoked "
                f"ticket_generation={claims.audience_generation} "
                f"local_generation={current_generation}",
                "error",
            )
            raise TicketValidationError(TicketErrorCode.REVOKED)
        if self.revocations.is_ticket_revoked(claims.ticket_id):
            self._log(
                f"CLUSTER ticket rejected: id={claims.ticket_id} "
                "reason=explicitly-revoked",
                "error",
            )
            raise TicketValidationError(TicketErrorCode.REVOKED)
        try:
            consumed = self.revocations.consume(claims.ticket_id, claims.expires_at)
        except RevocationCapacityError as error:
            raise TicketValidationError(TicketErrorCode.CACHE_FULL) from error
        if not consumed:
            raise TicketValidationError(TicketErrorCode.REPLAYED)
        return claims

    def _verify_signature(self, token: str) -> TicketClaims:
        if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            raise TicketValidationError(TicketErrorCode.MALFORMED)
        try:
            prefix, payload_text, signature_text = token.split(".")
            if prefix != "nst1":
                raise TicketValidationError(TicketErrorCode.MALFORMED)
            payload = _b64decode(payload_text)
            self._key.verify(_b64decode(signature_text), payload)
            return TicketClaims.from_dict(json.loads(payload.decode("utf-8")))
        except TicketValidationError:
            raise
        except InvalidSignature as error:
            raise TicketValidationError(TicketErrorCode.INVALID_SIGNATURE) from error
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TicketValidationError(TicketErrorCode.MALFORMED) from error
