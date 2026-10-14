"""Tunnel-only lazy HLS manifest and segment routes."""

import math
from urllib.parse import quote

from src.core.adaptive_streaming import (
    AdaptiveStreamingError,
    SEGMENT_SECONDS,
    TranscodingBusyError,
    TranscodingMemoryLimitError,
    TranscodingTimeoutError,
    available_variants,
    cached_segment_count,
    get_or_create_segment,
    get_or_create_audio_segment,
    probe_duration,
    segment_count,
)
from src.core.embedded_tracks import EmbeddedTrackError, probe_hls_tracks
import src.deps as deps
import src.state as state
from src.core.shared_paths import resolve_shared_path
from ..tunnel import _uses_public_access_policy


class StreamingRoutesMixin:

    @staticmethod
    def _hls_audio_tracks(target):
        try:
            return probe_hls_tracks(target).audio
        except (EmbeddedTrackError, OSError, TypeError):
            return ()

    def _stream_target(self, params):
        if not _uses_public_access_policy(self):
            self.send_error_json("Adaptive streaming is tunnel-only", 404)
            return None
        rel = params.get("path", [""])[0]
        cluster_path = self._parse_cluster_virtual_path(rel) if rel else None
        if cluster_path:
            node_id, _remote_path = cluster_path
            controller = getattr(state, "_cluster_controller", None)
            capabilities = (
                self._cluster_node_media_capabilities(controller, node_id)
                if controller is not None else {"known": False}
            )
            self.send_json({
                "status": "unavailable",
                "error": "cluster_transcoding_unavailable",
                "code": "streaming.cluster_transcoding_unavailable",
                "fallback": "direct_play",
                "node_id": node_id,
                "slave_hls_transcoding": capabilities.get("hls_transcoding")
                if capabilities.get("known") is True else None,
                "message": "Cluster media is direct-play only; HLS transcoding is not relayed across cluster nodes.",
            }, 501)
            return None
        if not deps.HAS_HLS_TRANSCODING:
            self.send_json({
                "status": "unavailable",
                "error": "ffmpeg_unavailable",
                "message": (
                    "Install a complete FFmpeg system package to enable "
                    "HLS transcoding."
                ),
            }, 501)
            return None
        resolved = resolve_shared_path(
            rel, visible=True, require_file=True,
            allowed_paths=self._guest_allowed_paths(),
        ) if rel else None
        target = resolved.path if resolved else None
        if target is None:
            self.send_error_json("File not found", 404)
            return None
        lock = self._lock_status(rel)
        if lock["locked"]:
            self._send_premium_locked(lock)
            return None
        return rel, target

    def _route_manifest(self, params):
        resolved = self._stream_target(params)
        if resolved is None:
            return
        rel, target = resolved
        variant = params.get("variant", [""])[0]
        preferred_variant = params.get("preferred_variant", [""])[0]
        variants = available_variants()
        if variant and variant not in variants:
            return self.send_error_json("Invalid HLS variant", 400)
        if preferred_variant and preferred_variant not in variants:
            return self.send_error_json("Invalid preferred HLS variant", 400)
        if variant and preferred_variant:
            return self.send_error_json("Conflicting HLS variant selection", 400)
        try:
            duration = probe_duration(target, guest=self._has_guest_session())
        except TranscodingBusyError as error:
            return self.send_error_json(
                f"HLS busy: {error}", 503, code="streaming.busy",
                domain="streaming", severity="warning", support_code="STRM-05",
            )
        except TranscodingMemoryLimitError:
            return self.send_json({
                "status": "retryable",
                "error": "ffmpeg_memory_limit",
                "message": "HLS transcoding exceeded its memory limit. Retry at a lower quality.",
            }, 503)
        except TranscodingTimeoutError as error:
            return self.send_error_json(
                f"HLS timeout: {error}", 504, code="streaming.timeout",
                domain="streaming", severity="warning", support_code="STRM-06",
            )
        except AdaptiveStreamingError as error:
            import src.state as state
            state._emit(f"HLS unavailable ({type(error).__name__})", "error")
            return self.send_error_json(
                "HLS unavailable", 422, code="streaming.unavailable",
                domain="streaming", support_code="STRM-01",
            )
        encoded_path = quote(rel, safe="")
        if not variant:
            lines = ["#EXTM3U", "#EXT-X-VERSION:3", "#EXT-X-INDEPENDENT-SEGMENTS"]
            try:
                audio_tracks = self._hls_audio_tracks(target)
            except EmbeddedTrackError:
                audio_tracks = ()
            has_audio = bool(audio_tracks)
            if has_audio:
                default_track = next(
                    (track for track in audio_tracks if track.default),
                    audio_tracks[0],
                )
                for position, track in enumerate(audio_tracks):
                    name = track.title or track.language or f"Audio {position + 1}"
                    language = f',LANGUAGE="{track.language}"' if track.language else ""
                    default = "YES" if track.index == default_track.index else "NO"
                    lines.append(
                        '#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="netshare-audio",'
                        f'NAME="{name}",DEFAULT={default},AUTOSELECT=YES{language},'
                        f'URI="/audio-manifest?path={encoded_path}&track={track.index}"'
                    )
            master_variants = (
                {preferred_variant: variants[preferred_variant]}
                if preferred_variant else variants
            )
            for name, profile in master_variants.items():
                height = profile["height"]
                resolution = f",RESOLUTION=1280x{height}" if height else ""
                audio = ',AUDIO="netshare-audio"' if has_audio else ""
                lines += [
                    f"#EXT-X-STREAM-INF:BANDWIDTH={profile['bandwidth']}{resolution}{audio}",
                    f"/manifest?path={encoded_path}&variant={name}",
                ]
        elif variant in variants:
            lines = [
                "#EXTM3U", "#EXT-X-VERSION:3",
                f"#EXT-X-TARGETDURATION:{math.ceil(SEGMENT_SECONDS)}",
                "#EXT-X-MEDIA-SEQUENCE:0", "#EXT-X-PLAYLIST-TYPE:VOD",
            ]
            count = segment_count(duration)
            for index in range(count):
                segment_duration = min(SEGMENT_SECONDS, duration - index * SEGMENT_SECONDS)
                lines += [
                    f"#EXTINF:{segment_duration:.3f},",
                    f"/segment?path={encoded_path}&variant={variant}&index={index}",
                ]
            lines.append("#EXT-X-ENDLIST")
        else:
            return self.send_error_json("Invalid HLS variant", 400)
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.apple.mpegurl")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Access-Control-Expose-Headers", "Content-Length, ETag")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _route_audio_manifest(self, params):
        resolved = self._stream_target(params)
        if resolved is None:
            return
        rel, target = resolved
        try:
            stream_index = int(params.get("track", ["-1"])[0])
            inventory = probe_hls_tracks(target)
            if stream_index not in {track.index for track in inventory.audio}:
                raise ValueError
            duration = probe_duration(target, guest=self._has_guest_session())
        except (ValueError, EmbeddedTrackError):
            return self.send_error_json("Invalid HLS audio track", 404)
        encoded_path = quote(rel, safe="")
        lines = [
            "#EXTM3U", "#EXT-X-VERSION:3",
            f"#EXT-X-TARGETDURATION:{math.ceil(SEGMENT_SECONDS)}",
            "#EXT-X-MEDIA-SEQUENCE:0", "#EXT-X-PLAYLIST-TYPE:VOD",
        ]
        for index in range(segment_count(duration)):
            segment_duration = min(SEGMENT_SECONDS, duration - index * SEGMENT_SECONDS)
            lines += [
                f"#EXTINF:{segment_duration:.3f},",
                f"/audio-segment?path={encoded_path}&track={stream_index}&index={index}",
            ]
        lines.append("#EXT-X-ENDLIST")
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.apple.mpegurl")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "private, no-store")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _route_audio_segment(self, params):
        resolved = self._stream_target(params)
        if resolved is None:
            return
        _, target = resolved
        try:
            stream_index = int(params.get("track", ["-1"])[0])
            index = int(params.get("index", ["-1"])[0])
            inventory = probe_hls_tracks(target)
            if stream_index not in {track.index for track in inventory.audio}:
                raise ValueError
            segment = get_or_create_audio_segment(
                target, stream_index, index, guest=self._has_guest_session(),
            )
            return self._serve_full(segment, segment.stat().st_size, "video/mp2t")
        except (ValueError, EmbeddedTrackError, AdaptiveStreamingError):
            return self.send_error_json("HLS audio segment unavailable", 422)

    def _route_segment(self, params):
        resolved = self._stream_target(params)
        if resolved is None:
            return
        _, target = resolved
        variant = params.get("variant", [""])[0]
        try:
            index = int(params.get("index", ["-1"])[0])
            count = cached_segment_count(target)
            if count is None:
                return self.send_error_json(
                    "HLS manifest required before requesting segments", 409,
                )
            if index < 0 or index >= count:
                return self.send_error_json("Invalid HLS segment", 404)
            segment = get_or_create_segment(
                target, variant, index, guest=self._has_guest_session(),
                include_audio=False,
            )
            return self._serve_full(segment, segment.stat().st_size, "video/mp2t")
        except TranscodingBusyError as error:
            return self.send_error_json(
                f"HLS busy: {error}", 503, code="streaming.busy",
                domain="streaming", severity="warning", support_code="STRM-05",
            )
        except TranscodingMemoryLimitError:
            return self.send_json({
                "status": "retryable",
                "error": "ffmpeg_memory_limit",
                "message": "HLS transcoding exceeded its memory limit. Retry at a lower quality.",
            }, 503)
        except TranscodingTimeoutError as error:
            return self.send_error_json(
                f"HLS timeout: {error}", 504, code="streaming.timeout",
                domain="streaming", severity="warning", support_code="STRM-06",
            )
        except (ValueError, AdaptiveStreamingError, EmbeddedTrackError) as error:
            import src.state as state
            state._emit(f"HLS segment unavailable ({type(error).__name__})", "error")
            return self.send_error_json(
                "HLS segment unavailable", 422,
                code="streaming.segment_unavailable", domain="streaming",
                support_code="STRM-02",
            )
