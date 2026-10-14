"""HTTP routes for browser-scoped read-only web sessions."""

from src.constants import VERSION
import src.state as state
from src.core.web_sessions import SessionCapacityError
from ..tunnel import _uses_public_access_policy


class WebSessionRoutesMixin:
    def _web_no_store_headers(self):
        return {"Cache-Control": "no-store", "Pragma": "no-cache", "Vary": "Origin"}

    def _web_session_payload(self, session, *, token=None):
        payload = {"authenticated": True}
        if token is not None:
            payload.update({"access_token": token, "token_type": "Bearer"})
        payload["session"] = session.public_dict()
        if token is not None:
            payload["server"] = {
                "id": state.SERVER_ID,
                "name": state.SERVER_NAME,
                "version": VERSION,
                "capabilities": [],
            }
        return payload

    def _route_web_session_create(self):
        identity = f"{self._client_ip()}:{state.SERVER_ID}"
        if not self._enforce_web_rate("auth-attempt", identity, 5, 60):
            return
        if not _uses_public_access_policy(self):
            return self.send_error_json(
                "Web authentication is tunnel-only", 403,
                code="web.auth.disabled", domain="web.auth",
                headers=self._web_no_store_headers(),
            )
        if not state.WEB_ACCESS_ENABLED:
            return self.send_error_json(
                "Web access is disabled", 403,
                code="web.auth.disabled", domain="web.auth",
                headers=self._web_no_store_headers(),
            )
        password = self.headers.get("X-Web-Password", "")
        if not state.verify_web_password(password):
            self._security_auth_failure("web_access_key")
            return self.send_error_json(
                "Invalid web password", 401,
                code="web.auth.invalid", domain="web.auth",
                headers=self._web_no_store_headers(),
            )
        self._security_auth_success()
        if not self._enforce_web_rate("auth-success", self._client_ip(), 10, 60 * 60):
            return
        try:
            session, token = state.WEB_SESSION_STORE.create(
                browser_family=self.headers.get("Sec-CH-UA", "unknown"),
                os_family=self.headers.get("Sec-CH-UA-Platform", "unknown"),
            )
        except SessionCapacityError:
            return self.send_error_json(
                "Web session capacity reached", 429,
                code="web.session.capacity", domain="web.session",
                headers=self._web_no_store_headers(),
            )
        return self.send_json(
            self._web_session_payload(session, token=token), 201,
            headers=self._web_no_store_headers(),
        )

    def _route_web_session_get(self):
        lookup = self._web_session_lookup()
        if lookup.status != "valid":
            return self._send_web_session_error(lookup.status)
        return self.send_json(
            self._web_session_payload(lookup.session),
            headers=self._web_no_store_headers(),
        )

    def _route_web_session_refresh(self):
        current = self._web_session_lookup(touch=False)
        identity = current.session.id if current.session else self._client_ip()
        if not self._enforce_web_rate("refresh", identity, 10, 5 * 60):
            return
        lookup, token = state.WEB_SESSION_STORE.refresh(self._web_bearer_token())
        if lookup.status != "valid":
            return self._send_web_session_error(lookup.status)
        return self.send_json(
            self._web_session_payload(lookup.session, token=token),
            headers=self._web_no_store_headers(),
        )

    def _route_web_session_delete(self):
        lookup = self._web_session_lookup(touch=False)
        if lookup.status != "valid":
            return self._send_web_session_error(lookup.status)
        state.WEB_SESSION_STORE.revoke(lookup.session.id)
        self.send_response(204)
        for name, value in self._web_no_store_headers().items():
            self.send_header(name, value)
        self._send_cors_headers()
        self.end_headers()

    def _route_web_sessions_list(self):
        return self.send_json(
            {"sessions": [session.public_dict(include_client=True) for session in state.WEB_SESSION_STORE.list()]},
            headers=self._web_no_store_headers(),
        )

    def _route_web_session_admin_delete(self, session_id):
        if not state.WEB_SESSION_STORE.revoke(session_id):
            return self.send_error_json(
                "Unknown web session", 404, code="web.session.unknown",
                domain="web.session", headers=self._web_no_store_headers(),
            )
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _route_web_sessions_revoke_all(self):
        revoked = state.WEB_SESSION_STORE.revoke_all()
        return self.send_json({
            "revoked": revoked,
            "web_credential_generation": state.WEB_CREDENTIAL_GENERATION,
        }, headers=self._web_no_store_headers())

    def _send_web_session_error(self, status):
        code = "web.session.expired" if status == "expired" else (
            "web.session.revoked" if status == "revoked" else "web.session.invalid"
        )
        return self.send_error_json(
            "Invalid web session", 401, code=code, domain="web.session",
            headers=self._web_no_store_headers(),
        )
