"""Guest-code exchange and request-scoped guest identity helpers."""

import json

import src.state as state
from src.core.guest_profiles import get_guest_profile_store


class GuestRoutesMixin:
    _GUEST_READ_ENDPOINTS = frozenset({
        "/list", "/search", "/file", "/thumbnail", "/art", "/waveform",
        "/media-analysis", "/manifest", "/segment",
    })

    def _guest_store(self):
        return get_guest_profile_store(state.GUEST_PROFILES_PATH)

    def _guest_session(self):
        return self._guest_store().verify_session(
            self.headers.get("X-Guest-Session", "").strip()
        )

    def _has_guest_session(self) -> bool:
        return self._guest_session() is not None

    def _reject_invalid_guest_session(self) -> bool:
        if self.headers.get("X-Guest-Session", "").strip() and not self._has_guest_session():
            self.send_error_json("Guest session invalid or expired", 401)
            return True
        return False

    def _guest_allowed_paths(self):
        session = self._guest_session()
        return session.allowed_paths if session is not None else None

    def _reject_guest_endpoint(self, endpoint: str) -> bool:
        if self._has_guest_session() and endpoint not in self._GUEST_READ_ENDPOINTS:
            self.send_error_json("Guest access is read-only and limited", 403)
            return True
        return False

    def _route_guest_session_create(self):
        key = self._rate_key("guest-code")
        if not state.auth_attempt_allowed(key):
            return self.send_error_json("Too many guest access attempts", 429)
        body = self._read_body(4 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            result = self._guest_store().exchange_code(str(payload.get("code", "")))
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            return self.send_error_json("Invalid guest access request", 400)
        if result is None:
            state.record_auth_failure(key)
            return self.send_error_json("Invalid guest code", 403)
        state.clear_auth_failures(key)
        self.send_json(result, 201)
