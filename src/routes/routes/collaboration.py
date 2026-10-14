"""Authenticated LAN routes for collaborative queues."""

import json

from src.core import collaborative_queue
from src.core.collaborative_queue import CollaborativeQueueError
from ..tunnel import _uses_public_access_policy


class CollaborationRoutesMixin:
    def _collaboration_device(self):
        return str(self.headers.get("X-Device-ID") or "")

    def _collaboration_body(self):
        body = self._read_body(32 * 1024)
        if body is None:
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.send_error_json("Invalid collaboration request", 400)
            return None

    def _collaboration_lan_guard(self):
        if _uses_public_access_policy(self):
            self.send_error_json("LAN only", 403)
            return False
        return True

    def _collaboration_host_guard(self):
        if not self._collaboration_lan_guard():
            return False
        if not self._has_full_write_access():
            self.send_error_json("Trusted device required", 403)
            return False
        return True

    def _collaboration_member_guard(self, room_id):
        if not self._collaboration_lan_guard():
            return False
        if self._has_full_write_access():
            return True
        ticket = self.headers.get("X-Room-Ticket", "").strip()
        if collaborative_queue.verify_member_ticket(
            room_id, self._collaboration_device(), ticket
        ):
            return True
        self.send_error_json("Valid room ticket required", 403)
        return False

    def _route_room_create(self):
        if not self._collaboration_host_guard():
            return
        payload = self._collaboration_body()
        if payload is None:
            return
        self._send_collaboration(lambda: collaborative_queue.create_room(self._collaboration_device(), payload), 201)

    def _route_room_join(self):
        if not self._collaboration_lan_guard():
            return
        payload = self._collaboration_body()
        if payload is None:
            return
        self._send_collaboration(lambda: collaborative_queue.join_room(self._collaboration_device(), payload.get("join_code", ""), payload.get("device_label", "")))

    def _route_room_get(self, room_id):
        if not self._collaboration_member_guard(room_id):
            return
        self._send_collaboration(lambda: collaborative_queue.snapshot(room_id, self._collaboration_device()))

    def _route_queue_add(self, room_id):
        if not self._collaboration_member_guard(room_id):
            return
        payload = self._collaboration_body()
        if payload is None:
            return
        self._send_collaboration(lambda: collaborative_queue.propose(room_id, self._collaboration_device(), payload.get("media_id", ""), payload.get("title", "")), 201)

    def _route_vote(self, room_id):
        if not self._collaboration_member_guard(room_id):
            return
        payload = self._collaboration_body()
        if payload is None:
            return
        self._send_collaboration(lambda: collaborative_queue.vote(room_id, self._collaboration_device(), payload.get("item_id", ""), payload.get("enabled", True)))

    def _route_room_action(self, room_id):
        if not self._collaboration_host_guard():
            return
        payload = self._collaboration_body()
        if payload is None:
            return
        self._send_collaboration(lambda: collaborative_queue.host_action(room_id, self._collaboration_device(), payload.get("action", ""), payload.get("target_id", "")))

    def _send_collaboration(self, action, status=200):
        try:
            self.send_json(action(), status)
        except CollaborativeQueueError as error:
            self.send_error_json(str(error), 400)
