"""Protocol-v2 discovery routes.

Only non-sensitive metadata is exposed before authentication so a Player can
decide whether it understands the server before entering credentials.
"""

import src.state as state
from src.constants import VERSION
from src.core.api_capabilities import (
    CLUSTER_CAPABILITY,
    HLS_TRANSCODING_CAPABILITY,
    HLS_GPU_TRANSCODING_CAPABILITY,
    AUDIO_ANALYSIS_CAPABILITY,
    VIDEO_THUMBNAILS_CAPABILITY,
    TLS_TOFU_CAPABILITY,
    build_api_descriptor,
    compatible_server_mode_descriptor,
)
import src.deps as deps
from src.core.adaptive_streaming import variant_descriptors
from ..tunnel import _uses_public_access_policy


class V2RoutesMixin:

    def _route_v2_capabilities(self):
        via_tunnel = _uses_public_access_policy(self)
        public_role = self._public_role() if via_tunnel else ""
        advertised_capabilities = []
        if state.FEATURE_FLAGS.get("cluster"):
            advertised_capabilities.append(CLUSTER_CAPABILITY)
        if deps.HAS_HLS_TRANSCODING:
            advertised_capabilities.append(HLS_TRANSCODING_CAPABILITY)
        if deps.FFMPEG_CAPABILITIES.hls_transcoding_gpu:
            advertised_capabilities.append(HLS_GPU_TRANSCODING_CAPABILITY)
        if deps.HAS_AUDIO_ANALYSIS:
            advertised_capabilities.append(AUDIO_ANALYSIS_CAPABILITY)
        if deps.HAS_VIDEO_THUMBNAILS:
            advertised_capabilities.append(VIDEO_THUMBNAILS_CAPABILITY)
        from src.core.server_tls import is_transport_tls_active
        if is_transport_tls_active():
            advertised_capabilities.append(TLS_TOFU_CAPABILITY)
        self.send_json({
            "api": build_api_descriptor(
                advertised_capabilities
            ),
            "server": {
                "id": state.SERVER_ID,
                "name": state.SERVER_NAME,
                "version": VERSION,
                "access_mode": "tunnel" if via_tunnel else "local",
            },
            "features": self._feature_payload(via_tunnel, public_role),
            "streaming": {
                "can_transcode": bool(deps.HAS_HLS_TRANSCODING),
                "connection": "tunnel" if via_tunnel else "lan",
                "profiles": variant_descriptors() if deps.HAS_HLS_TRANSCODING else [],
                "compatible_server_mode_v1": compatible_server_mode_descriptor(
                    variant_descriptors()
                ),
            },
        })
