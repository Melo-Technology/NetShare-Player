"""B1 Player-to-Player ephemeral invitation routes (metadata only)."""
import json

from src.core.p2p_invitations import (
    MAX_ENVELOPE_BYTES,
    P2PInvitationError,
    p2p_invitation_store,
)


class P2PInvitationRoutesMixin:
    def _route_p2p_invitation_create(self):
        body = self._read_body(MAX_ENVELOPE_BYTES)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            envelope = payload.get("envelope") if isinstance(payload, dict) else None
            created = p2p_invitation_store.create(
                envelope,
                int(payload.get("ttl_seconds", 300)),
                int(payload.get("max_accesses", 1)),
            )
            self.send_json(created, 201)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            self.send_error_json("Invalid invitation request", 400)
        except P2PInvitationError as error:
            self.send_error_json(str(error), 400)

    def _p2p_invitation_token(self) -> str:
        return str(self.headers.get("X-P2P-Invitation-Token", "")).strip()

    def _route_p2p_invitation_get(self):
        grant = p2p_invitation_store.resolve(self._p2p_invitation_token())
        if grant is None:
            return self.send_error_json("Invitation unavailable or expired", 404)
        self.send_json({
            "id": grant.invitation_id,
            "envelope": grant.envelope,
            "expires_at": grant.expires_at,
            "remaining_accesses": grant.remaining_accesses,
        })


    def _route_p2p_invitation_sender_status(self, invitation_id: str):
        status = p2p_invitation_store.sender_status(invitation_id)
        if status is None:
            return self.send_error_json("Invitation not found or expired", 404)
        self.send_json(status)

    def _route_p2p_invitation_consume(self):
        body = self._read_body(8 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            invitation_id = str(payload.get("invitation_id", ""))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            return self.send_error_json("Invalid invitation consume request", 400)
        grant = p2p_invitation_store.consume(self._p2p_invitation_token(), invitation_id)
        if grant is None:
            return self.send_error_json("Invitation already consumed or expired", 410)
        self.send_json({
            "ok": True,
            "id": grant.invitation_id,
            "remaining_accesses": grant.remaining_accesses,
        })

    def _route_p2p_invitation_revoke(self, invitation_id: str):
        if p2p_invitation_store.revoke(invitation_id):
            return self.send_json({"ok": True})
        self.send_error_json("Invitation not found", 404)
