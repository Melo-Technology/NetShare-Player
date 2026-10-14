"""Versioned API capability negotiation shared by HTTP transports.

The protocol range is deliberately independent from the application version:
patch releases can evolve without forcing otherwise compatible Players to
upgrade.  Future transports (for example cluster nodes) can reuse the same
negotiation without importing the HTTP handler.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


API_SCHEMA_VERSION = 1
API_PROTOCOL_MINIMUM = 1
API_PROTOCOL_CURRENT = 2

CAPABILITY_ENDPOINT = "api_v2.capabilities"
RESUMABLE_TRANSFERS_CAPABILITY = "transfers.resumable_multi_file"
EPHEMERAL_SHARE_CAPABILITY = "sharing.ephemeral_qr"
NETWORK_DIAGNOSTICS_CAPABILITY = "diagnostics.private_network"
SMART_COLLECTIONS_CAPABILITY = "collections.smart_local"
UNIVERSAL_RESUME_CAPABILITY = "resume.universal_handoff"
OFFLINE_MANIFEST_CAPABILITY = "offline.manifests"
COLLABORATIVE_QUEUE_CAPABILITY = "collaboration.queue_lan"
SYNC_PLAYBACK_CAPABILITY = "sync.playback_lan"
CLUSTER_CAPABILITY = "cluster.master_slave_relay"
HLS_TRANSCODING_CAPABILITY = "streaming.hls_transcoding"
HLS_GPU_TRANSCODING_CAPABILITY = "streaming.hls_transcoding_gpu"
COMPATIBLE_SERVER_MODE_CAPABILITY = "streaming.compatible_server_mode_v1"
AUDIO_ANALYSIS_CAPABILITY = "media.audio_analysis"
VIDEO_THUMBNAILS_CAPABILITY = "media.video_thumbnails"
MULTIROOT_CAPABILITY = "sharing.multi_root_v1"
TLS_TOFU_CAPABILITY = "transport.tls_tofu_v1"


class NegotiationStatus(str, Enum):
    """Exhaustive outcomes for two bounded protocol ranges."""

    COMPATIBLE = "compatible"
    CLIENT_TOO_OLD = "client_too_old"
    SERVER_TOO_OLD = "server_too_old"
    INVALID_RANGE = "invalid_range"


@dataclass(frozen=True)
class NegotiationResult:
    status: NegotiationStatus
    selected_protocol: int | None = None

    @property
    def compatible(self) -> bool:
        return self.status is NegotiationStatus.COMPATIBLE


def negotiate_protocol(
    client_minimum: int,
    client_current: int,
    server_minimum: int = API_PROTOCOL_MINIMUM,
    server_current: int = API_PROTOCOL_CURRENT,
) -> NegotiationResult:
    """Select the newest protocol supported by both bounded ranges."""
    values = (client_minimum, client_current, server_minimum, server_current)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        return NegotiationResult(NegotiationStatus.INVALID_RANGE)
    if min(values) < 1 or client_minimum > client_current or server_minimum > server_current:
        return NegotiationResult(NegotiationStatus.INVALID_RANGE)
    if client_current < server_minimum:
        return NegotiationResult(NegotiationStatus.CLIENT_TOO_OLD)
    if server_current < client_minimum:
        return NegotiationResult(NegotiationStatus.SERVER_TOO_OLD)
    return NegotiationResult(
        NegotiationStatus.COMPATIBLE,
        min(client_current, server_current),
    )


def build_api_descriptor(capabilities: Iterable[str] = ()) -> dict:
    """Return the stable descriptor embedded in `/ping` and API v2."""
    normalized = sorted({
        str(capability).strip()
        for capability in capabilities
        if str(capability).strip()
    } | {
        CAPABILITY_ENDPOINT,
        COLLABORATIVE_QUEUE_CAPABILITY,
        SMART_COLLECTIONS_CAPABILITY,
        SYNC_PLAYBACK_CAPABILITY,
        NETWORK_DIAGNOSTICS_CAPABILITY,
        OFFLINE_MANIFEST_CAPABILITY,
        UNIVERSAL_RESUME_CAPABILITY,
        EPHEMERAL_SHARE_CAPABILITY,
        RESUMABLE_TRANSFERS_CAPABILITY,
        MULTIROOT_CAPABILITY,
        COMPATIBLE_SERVER_MODE_CAPABILITY,
    })
    return {
        "schema": API_SCHEMA_VERSION,
        "minimum_protocol": API_PROTOCOL_MINIMUM,
        "protocol": API_PROTOCOL_CURRENT,
        "capabilities": normalized,
    }


def compatible_server_mode_descriptor(profiles: list[dict]) -> dict:
    """Describe the inactive v1 contract without enabling LAN or tunnel use."""
    return {
        "available": False,
        "profiles": profiles,
        "output": {
            "video_codecs": ["h264"],
            "audio_codecs": ["aac"],
            "containers": ["mpegts"],
        },
        "connections": {
            "lan": False,
            "tunnel": False,
        },
        "guest": {
            "allowed": False,
        },
        "consent": {
            "required": True,
            "implemented": False,
        },
    }
