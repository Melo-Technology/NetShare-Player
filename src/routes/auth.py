"""
Authentication and authorization: passwords (tunnel vs LAN), device
credentials, and the "public_role" (admin/community) resolution used
by the tunnel-facing endpoints.
"""

import hmac
from urllib.parse import parse_qs, unquote, urlparse

import src.state as state
from .tunnel import _uses_public_access_policy


class AuthMixin:
    """Password / device-credential / role checks shared across routes."""

    def _check_password(self) -> bool:
        """Validate X-Password and report failures to the security monitor."""
        public_access = _uses_public_access_policy(self)
        kind = "public_access_key" if public_access else "local_password"
        key = self._rate_key("password:public" if public_access else "password:local")
        if not state.auth_attempt_allowed(key):
            self._auth_rate_limited = True
            self._security_auth_failure(kind)
            return False
        if public_access:
            if not state.has_community_password() and not state.has_admin_password():
                state.record_auth_failure(key)
                self._security_auth_failure(kind)
                return False
            received = unquote(self.headers.get("X-Password", "")).strip()
            ok = bool(
                state.verify_community_password(received)
                or state.verify_admin_password(received)
                or (
                    state.TUNNEL_PASSWORD
                    and hmac.compare_digest(received, state.TUNNEL_PASSWORD)
                )
            )
        else:
            if not state.LOCAL_PASSWORD:
                self._security_auth_success()
                return True
            received = unquote(self.headers.get("X-Password", "")).strip()
            ok = hmac.compare_digest(received, state.LOCAL_PASSWORD)
        if ok:
            state.clear_auth_failures(key)
            self._security_auth_success()
        else:
            state.record_auth_failure(key)
            self._security_auth_failure(kind)
        return ok

    def _reject_misplaced_web_password(self, endpoint: str) -> bool:
        if self.headers.get("X-Web-Password") is not None and endpoint != "/api/v2/web/session":
            self.send_error_json(
                "X-Web-Password is accepted only for web session creation",
                400, code="web.auth.header_not_allowed", domain="web.auth",
                headers=self._web_no_store_headers(),
            )
            return True
        return False

    def _web_bearer_token(self) -> str:
        authorization = self.headers.get("Authorization", "").strip()
        if not authorization:
            return ""
        parts = authorization.split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            return ""
        return parts[1]

    def _web_session_lookup(self, *, touch: bool = True):
        return state.WEB_SESSION_STORE.get(self._web_bearer_token(), touch=touch)

    def _has_web_session(self) -> bool:
        return self._web_session_lookup().status == "valid"

    def _authorize_web_read(self, endpoint: str) -> bool | None:
        """Return None without Bearer, otherwise authorize or emit an error."""
        if not self.headers.get("Authorization"):
            return None
        # Paired mobile Bearers are namespaced by their mandatory device ID
        # and must continue through the existing device-credential path.
        if self._device_id():
            return None
        lookup = self._web_session_lookup()
        if lookup.status != "valid":
            code = "web.session.expired" if lookup.status == "expired" else (
                "web.session.revoked" if lookup.status == "revoked" else "web.session.invalid"
            )
            self.send_error_json(
                "Invalid web session", 401, code=code, domain="web.session",
                headers=self._web_no_store_headers(),
            )
            return False
        allowed = {
            "/api/v2/capabilities", "/list", "/search", "/file", "/thumbnail",
            "/art", "/waveform", "/lyrics", "/document", "/manifest", "/segment",
            "/audio-manifest", "/audio-segment", "/media-analysis",
        }
        if endpoint not in allowed:
            self.send_error_json(
                "Web sessions are read-only", 403,
                code="web.session.read_only", domain="web.session",
                headers=self._web_no_store_headers(),
            )
            return False
        return True

    def _reject_web_mutation(self) -> bool:
        if not self.headers.get("Authorization"):
            return False
        if self._web_session_lookup(touch=False).status != "valid":
            return False
        self.send_error_json(
            "Web sessions are read-only", 403,
            code="web.session.read_only", domain="web.session",
            headers=self._web_no_store_headers(),
        )
        return True

    def _public_role(self) -> str:
        if not _uses_public_access_policy(self):
            return ""
        received = unquote(self.headers.get("X-Password", "")).strip()
        if state.verify_admin_password(received) or (
            state.TUNNEL_PASSWORD
            and hmac.compare_digest(received, state.TUNNEL_PASSWORD)
        ):
            return "admin"
        if state.verify_community_password(received):
            return "community"
        return ""

    def _has_full_write_access(self) -> bool:
        if _uses_public_access_policy(self):
            return self._public_role() == "admin"
        return self._has_device_credential()

    def _device_credential(self) -> str:
        authorization = self.headers.get("Authorization", "").strip()
        if authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return self.headers.get("X-Device-Credential", "").strip()

    def _has_device_credential(self, device_id: str | None = None) -> bool:
        return state.verify_device_credential(
            device_id if device_id is not None else self._device_id(),
            self._device_credential(),
        )

    def _has_upload_access(self) -> bool:
        if _uses_public_access_policy(self):
            role = self._public_role()
            return role == "admin" or (
                role == "community" and state.COMMUNITY_UPLOAD
            )
        return self._has_full_write_access()

    def _community_home(self) -> str:
        return "/" if state.COMMUNITY_BROWSE_ROOT else "/incoming"

    def _device_id(self) -> str:
        header_id = unquote(self.headers.get("X-Device-ID", "")).strip()
        if header_id:
            return header_id
        return unquote(
            parse_qs(urlparse(self.path).query).get("device_id", [""])[0]
        ).strip()
