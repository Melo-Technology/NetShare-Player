"""
Listening-session sync groups (LAN-only, device-credential gated):
link/create/join, invite renewal, ping (position sync), state, members,
leave, remove.
"""

import base64
import json
from io import BytesIO

from src.core import session_sync
from ..tunnel import _uses_public_access_policy


class SessionGroupRoutesMixin:

    def _verify_session_confirmation(self, code: str, rate_key: str) -> bool:
        """Accept the desktop write OTP or the configured authenticator TOTP."""
        import src.state as state
        if not state.auth_attempt_allowed(rate_key):
            self.send_error_json("Too many one-time code attempts", 429)
            return False
        if not (state.consume_write_otp(code) or state.verify_totp(code)):
            state.record_auth_failure(rate_key)
            self.send_error_json("Invalid one-time code", 403)
            return False
        state.clear_auth_failures(rate_key)
        return True

    def _session_local_guard(self) -> bool:
        if _uses_public_access_policy(self):
            self.send_error_json("Local network only", 403)
            return False
        if not self._check_password():
            self.send_error_json("Unauthorized", 401)
            return False
        if not self._has_device_credential():
            self.send_error_json("Valid device credential required", 403)
            return False
        return True

    def _route_session_group_link(self):
        if not self._session_local_guard():
            return
        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_error_json("Invalid JSON body", 400)
        device_id = str(payload.get("device_id", "")).strip()
        if device_id != self._device_id() or not self._has_device_credential(device_id):
            return self.send_error_json("Trusted device required", 403)
        rate_key = self._rate_key("totp-session-link")
        if not self._verify_session_confirmation(
            str(payload.get("code", "")), rate_key
        ):
            return
        invite = str(payload.get("invite_code", "")).strip()
        result = (
            session_sync.join_group(device_id, invite, str(payload.get("device_label", "")))
            if invite else session_sync.create_group(
                device_id, str(payload.get("group_name", "")),
                str(payload.get("device_label", "")),
            )
        )
        if result["status"] != "ok":
            return self.send_json(result, 409 if result["status"] == "group_full" else 403)
        self._add_session_qr(result)
        self.send_json(result)

    def _add_session_qr(self, result: dict):
        if not result.get("invite_code"):
            return
        try:
            import qrcode
            qr_payload = json.dumps({"type": "netshare-session-group", "code": result["invite_code"]})
            image = qrcode.make(qr_payload)
            buffer = BytesIO()
            image.save(buffer, format="PNG")
            result["qr_png"] = base64.b64encode(buffer.getvalue()).decode("ascii")
        except Exception:
            result["qr_png"] = None

    def _route_session_group_invite(self):
        if not self._session_local_guard():
            return
        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_error_json("Invalid JSON body", 400)
        device_id = self._device_id()
        if str(payload.get("device_id", "")).strip() != device_id:
            return self.send_error_json("Device ID mismatch", 403)
        rate_key = self._rate_key("totp-session-invite")
        if not self._verify_session_confirmation(
            str(payload.get("code", "")), rate_key
        ):
            return
        result = session_sync.renew_invite(
            str(payload.get("session_group_id", "")), device_id,
        )
        if result["status"] != "ok":
            return self.send_json(result, 403)
        self._add_session_qr(result)
        self.send_json(result)

    def _route_session_group_ping(self):
        if not self._session_local_guard():
            return
        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            device_id = self._device_id()
            result = session_sync.update_state(
                str(payload.get("session_group_id", "")), device_id,
                str(payload.get("track_id", "")), int(payload.get("position_ms", 0)),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return self.send_error_json("Invalid JSON body", 400)
        self.send_json(result, 200 if result["status"] == "ok" else 403)

    def _route_session_group_state(self, params):
        if not self._session_local_guard():
            return
        result = session_sync.get_state(
            params.get("session_group_id", [""])[0], self._device_id()
        )
        self.send_json(result, 200 if result["status"] == "ok" else 403)

    def _route_session_group_members(self, params):
        if not self._session_local_guard():
            return
        result = session_sync.list_members(
            params.get("session_group_id", [""])[0], self._device_id()
        )
        self.send_json(result, 200 if result["status"] == "ok" else 403)

    def _session_action_payload(self) -> dict | None:
        body = self._read_body(16 * 1024)
        if body is None:
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
            if isinstance(payload, dict):
                return payload
            self.send_error_json("Invalid JSON body", 400)
            return None
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error_json("Invalid JSON body", 400)
            return None

    def _route_session_group_leave(self):
        if not self._session_local_guard():
            return
        payload = self._session_action_payload()
        if payload is None:
            return
        device_id = self._device_id()
        if str(payload.get("device_id", "")).strip() != device_id:
            return self.send_error_json("Device ID mismatch", 403)
        result = session_sync.leave_group(
            str(payload.get("session_group_id", "")), device_id,
        )
        self.send_json(result, 200 if result["status"] == "ok" else 403)

    def _route_session_group_remove(self):
        if not self._session_local_guard():
            return
        payload = self._session_action_payload()
        if payload is None:
            return
        requester_id = self._device_id()
        if str(payload.get("device_id", "")).strip() != requester_id:
            return self.send_error_json("Device ID mismatch", 403)
        result = session_sync.remove_member(
            str(payload.get("session_group_id", "")), requester_id,
            str(payload.get("target_device_id", "")).strip(),
        )
        status = 200 if result["status"] == "ok" else (404 if result["status"] == "not_found" else 403)
        self.send_json(result, status)

    def _route_resume_update(self):
        if not self._session_local_guard():
            return
        payload = self._session_action_payload()
        if payload is None:
            return
        result = session_sync.update_resume(
            str(payload.get("session_group_id", "")),
            self._device_id(),
            str(payload.get("media_id", "")),
            str(payload.get("media_type", "")),
            payload.get("position"),
        )
        self.send_json(result, 200 if result["status"] == "ok" else 400 if result["status"] == "invalid" else 403)

    def _route_resume_history(self, params):
        if not self._session_local_guard():
            return
        try:
            result = session_sync.get_resume_history(
                params.get("session_group_id", [""])[0],
                self._device_id(),
                int(params.get("offset", ["0"])[0]),
                int(params.get("limit", ["20"])[0]),
            )
        except ValueError:
            return self.send_error_json("Invalid pagination", 400)
        self.send_json(result, 200 if result["status"] == "ok" else 403)

    def _route_handoff_request(self):
        if not self._session_local_guard():
            return
        payload = self._session_action_payload()
        if payload is None:
            return
        result = session_sync.request_handoff(
            str(payload.get("session_group_id", "")),
            self._device_id(),
            str(payload.get("target_device_id", "")),
            str(payload.get("media_id", "")),
            str(payload.get("media_type", "")),
            payload.get("position"),
        )
        status = 202 if result["status"] == "pending" else 409 if result["status"] == "busy" else 400 if result["status"] == "invalid" else 403
        self.send_json(result, status)

    def _route_handoff_respond(self):
        if not self._session_local_guard():
            return
        payload = self._session_action_payload()
        if payload is None:
            return
        result = session_sync.respond_handoff(
            str(payload.get("session_group_id", "")),
            self._device_id(),
            str(payload.get("handoff_id", "")),
            payload.get("accepted") is True,
        )
        status = 200 if result["status"] == "ok" else 404 if result["status"] == "not_found" else 403
        self.send_json(result, status)
