"""
Premium-folder unlock codes: lock-status resolution used by nearly every
other route mixin, plus the /redeem and /device/migrate endpoints
themselves.
"""

import json

import src.state as state
from src.core import unlock_codes
from ..tunnel import _uses_public_access_policy


class PremiumRoutesMixin:

    def _lock_status(self, rel_path: str) -> dict:
        """Premium-folder lock status for rel_path, scoped to this device."""
        device_id = self._device_id()
        if not _uses_public_access_policy(self) and not self._has_device_credential(device_id):
            device_id = ""
        return unlock_codes.lock_status_for_path(rel_path, device_id)

    def _send_premium_locked(self, lock: dict):
        return self.send_json({
            "error": "premium_locked",
            "folder_path": lock["folder_path"],
            "label": lock["label"],
            "price_note": lock["price_note"],
        }, 403)

    def _route_redeem(self):
        """Redeem a premium-folder unlock code for the requesting device."""
        if not _uses_public_access_policy(self) and not self._has_device_credential():
            return self.send_error_json("Valid device credential required", 403)
        key = self._rate_key("redeem")
        if not state.auth_attempt_allowed(key):
            return self.send_error_json("Too many redeem attempts", 429)
        body = self._read_body(4 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_error_json("Invalid JSON body", 400)
        code = str(payload.get("code", "")).strip()
        device_id = str(payload.get("device_id", "")).strip()
        if not code or not device_id:
            return self.send_error_json("Missing 'code' or 'device_id'", 400)
        result = unlock_codes.redeem_code(code, device_id)
        if result["status"] == "ok":
            state.clear_auth_failures(key)
            state._emit(
                f"PREMIUM code redeemed for {result['folder_path']}  [{self.client_address[0]}]",
                "ok",
            )
            return self.send_json(result)
        state.record_auth_failure(key)
        status_codes = {
            "invalid": 404,
            "revoked": 403,
            "expired": 410,
            "already_used": 409,
        }
        self.send_json(result, status_codes.get(result["status"], 400))

    def _route_device_migrate(self):
        """Replace a legacy app-install ID with a per-server pseudonym."""
        body = self._read_body(4 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_error_json("Invalid JSON body", 400)
        previous = str(payload.get("previous_device_id", "")).strip()
        current = str(payload.get("device_id", "")).strip()
        if not previous or not current:
            return self.send_error_json("Missing device identifiers", 400)
        if not state.verify_device_credential(previous, self._device_credential()):
            return self.send_error_json("Previous device credential required", 403)
        challenge = str(payload.get("challenge", "")).strip()
        if not challenge:
            return self.send_json({
                "status": "challenge",
                "challenge": state.create_migration_challenge(previous, current),
                "expires_in": state.MIGRATION_CHALLENGE_TTL_SECONDS,
            })
        if not state.consume_migration_challenge(challenge, previous, current):
            return self.send_error_json("Invalid or expired migration challenge", 403)
        migrated_grants = unlock_codes.migrate_device_id(previous, current)
        migrated_trust = state.migrate_trusted_device(previous, current)
        state._emit(
            f"DEVICE migration succeeded {previous[-6:]} -> {current[-6:]} "
            f"[{self.client_address[0]}]",
            "ok",
        )
        self.send_json({
            "ok": True,
            "migrated_grants": migrated_grants,
            "migrated_trust": migrated_trust,
        })
