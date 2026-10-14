"""
Server metadata (/ping) and local trusted-device pairing
(/setup-totp, /register-device).
"""

import base64
import json
from io import BytesIO

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
from ..tunnel import _is_lan_request, _uses_public_access_policy

_TEXT_EDIT_EXTS = {
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".xml", ".html",
    ".htm", ".css", ".js", ".py", ".log", ".ini", ".conf", ".yaml", ".yml",
    ".rtf",
}


class PingRoutesMixin:

    def _feature_payload(self, via_tunnel: bool, public_role: str) -> dict:
        """Build legacy feature flags shared by `/ping` and API v2."""
        return {
            "upload": bool(state.FEATURE_FLAGS.get("upload"))
                      and (public_role != "community" or state.COMMUNITY_UPLOAD),
            "download": public_role != "community" or state.COMMUNITY_DOWNLOAD,
            "browse_root": public_role != "community" or state.COMMUNITY_BROWSE_ROOT,
            "document_edit": bool(state.FEATURE_FLAGS.get("document_edit"))
                             and public_role != "community",
            "write_pairing": bool(state.FEATURE_FLAGS.get("write_pairing"))
                             and not via_tunnel,
            "write_otp_ttl": 0,
            "write_token_ttl": 0,
            "editable_extensions": sorted(_TEXT_EDIT_EXTS),
            "office_edit_mode": "download_edit_upload",
            "public_upload_mode": state.PUBLIC_UPLOAD_MODE,
        }

    def _route_ping(self, params):
        """Return server metadata and feature availability to the client."""
        from src.core.file_index import _file_index
        public_access = _uses_public_access_policy(self)
        public_role = self._public_role() if public_access else ""
        device_id = self.headers.get("X-Device-ID", "").strip()
        guest_session = self._guest_session()
        linked_slave = self._is_linked_cluster_slave()
        cluster_runtime = getattr(
            getattr(state, "_cluster_runtime", None), "runtime", None
        )
        fallback_check = getattr(cluster_runtime, "direct_http_enabled", None)
        fallback_enabled = bool(
            linked_slave
            and callable(fallback_check)
            and fallback_check()
        )
        fallback_payload = getattr(cluster_runtime, "fallback_payload", None)
        fallback_master = (
            fallback_payload()
            if fallback_enabled and callable(fallback_payload)
            else {}
        )
        ws_port    = None
        if state._ws_manager is not None:
            try:
                ws_port = int(self.server.server_address[1]) + 1
            except Exception:
                pass
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
        from src.core.server_tls import is_transport_tls_active, tls_identity_descriptor
        tls_active = is_transport_tls_active()
        if tls_active:
            advertised_capabilities.append(TLS_TOFU_CAPABILITY)
        self.send_json({
            "name":               state.SERVER_NAME,
            "server_id":          state.SERVER_ID,
            "version":            VERSION,
            "root":               state.ROOT_DIR.name or str(state.ROOT_DIR),
            "roots":              [
                {"slot": root.slot, "name": root.name}
                for root in state.SHARED_ROOTS
            ],
            "root_count":         len(state.SHARED_ROOTS),
            "ws_port":            ws_port,
            "index_ready":        _file_index.ready,
            "index_total":        _file_index.total,
            "requires_password":  bool(
                (state.has_community_password() or state.has_admin_password())
                if public_access else state.LOCAL_PASSWORD
            ),
            "connectable":        not linked_slave or fallback_enabled,
            "cluster_member":     {
                "role": "slave" if linked_slave else state.effective_cluster_role(),
                "linked": linked_slave,
                "fallback": fallback_enabled,
            },
            "cluster_fallback":   {
                "active": fallback_enabled,
                "master_name": fallback_master.get("name", ""),
                "master_url": fallback_master.get("url", ""),
            },
            "access_mode":        "tunnel" if public_access else "local",
            "mode":               "public" if public_access else "local",
            "public_role":        public_role,
            "trusted":            self._has_device_credential(device_id) if device_id and not public_access else False,
            "tls_identity":        tls_identity_descriptor(state._CONFIG_DIR, state.SERVER_ID) if tls_active else None,
            "guest":              guest_session is not None,
            "guest_profile":      (
                {"id": guest_session.profile_id, "name": guest_session.profile_name}
                if guest_session is not None else None
            ),
            # Old Players ignore unknown top-level keys; keeping the legacy
            # feature block untouched makes protocol discovery additive.
            "api":                 build_api_descriptor(advertised_capabilities),
            "streaming": {
                "can_transcode": bool(deps.HAS_HLS_TRANSCODING),
                "connection": "tunnel" if public_access else "lan",
                "profiles": variant_descriptors() if deps.HAS_HLS_TRANSCODING else [],
                "compatible_server_mode_v1": compatible_server_mode_descriptor(
                    variant_descriptors()
                ),
            },
            "features":            self._feature_payload(public_access, public_role),
        })

    def _route_setup_totp(self):
        """Create a TOTP secret and QR payload for local trusted-device pairing."""
        if not _is_lan_request(self):
            return self.send_error_json("Local network only", 403)
        if not self._check_password():
            return self.send_error_json(
                "Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized",
                429 if getattr(self, "_auth_rate_limited", False) else 401,
            )
        try:
            import qrcode
            uri = state.pyotp.TOTP(state.TOTP_SECRET).provisioning_uri(
                name=state.SERVER_NAME,
                issuer_name="NetShare Server",
            )
            img = qrcode.make(uri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            qr_png = base64.b64encode(buf.getvalue()).decode("ascii")
            return self.send_json({
                "secret": state.TOTP_SECRET,
                "otpauth_uri": uri,
                "qr_png": qr_png,
            })
        except Exception as error:
            state._emit(f"PAIRING QR failed ({type(error).__name__})", "error")
            return self.send_error_json(
                "Could not build TOTP QR", 500, code="security.totp_qr_failed",
                domain="security", support_code="SEC-04",
            )

    def _route_register_device(self):
        """Register a trusted device after validating a local one-time code."""
        if not _is_lan_request(self):
            return self.send_error_json("Local network only", 403)
        if not self._check_password():
            return self.send_error_json(
                "Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized",
                429 if getattr(self, "_auth_rate_limited", False) else 401,
            )
        key = self._rate_key("totp-register")
        if not state.auth_attempt_allowed(key):
            return self.send_error_json("Too many pairing attempts", 429)
        body = self._read_body(8 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_error_json("Invalid JSON body", 400)
        credential = state.register_device(
            str(payload.get("device_id", "")).strip(),
            str(payload.get("code", "")).strip(),
        )
        if not credential:
            state.record_auth_failure(key)
            return self.send_error_json("Invalid or expired pairing code", 403)
        state.clear_auth_failures(key)
        self.send_json({"ok": True, "device_credential": credential})
