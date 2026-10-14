"""LAN-only direct-play synchronization routes."""

import json

from src.core import sync_room
from src.core.sync_room import SyncRoomError
from ..tunnel import _uses_public_access_policy


class SyncRoomRoutesMixin:
    def _sync_lan_guard(self):
        if _uses_public_access_policy(self):
            self.send_error_json("LAN only", 403)
            return False
        return True

    def _sync_host_guard(self):
        if not self._sync_lan_guard():
            return False
        if not self._has_full_write_access():
            self.send_error_json("Trusted device required", 403)
            return False
        return True

    def _sync_member_guard(self, room_id):
        if not self._sync_lan_guard():
            return False
        if self._has_full_write_access():
            return True
        ticket = self.headers.get("X-Room-Ticket", "").strip()
        if sync_room.verify_member_ticket(room_id, self._sync_device(), ticket):
            return True
        self.send_error_json("Valid room ticket required", 403)
        return False

    def _sync_body(self):
        body = self._read_body(32 * 1024)
        if body is None:
            return None
        try:
            value = json.loads(body.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.send_error_json("Invalid sync request", 400)
            return None

    def _sync_device(self):
        return str(self.headers.get("X-Device-ID") or "")

    def _sync_send(self, action, status=200):
        try:
            self.send_json(action(), status)
        except SyncRoomError as error:
            self.send_error_json(str(error), 400)

    def _route_sync_create(self):
        if not self._sync_host_guard():
            return
        body = self._sync_body()
        if body is not None:
            self._sync_send(lambda: sync_room.create(self._sync_device(), body.get("media_id", ""), body.get("media_type", "")), 201)

    def _route_sync_join(self):
        if not self._sync_lan_guard():
            return
        body = self._sync_body()
        if body is not None:
            self._sync_send(lambda: sync_room.join(self._sync_device(), body.get("join_code", ""), body.get("media_id", "")))

    def _route_sync_get(self, room_id):
        if self._sync_member_guard(room_id):
            self._sync_send(lambda: sync_room.snapshot(room_id, self._sync_device()))

    def _route_sync_report(self, room_id):
        if not self._sync_member_guard(room_id):
            return
        body = self._sync_body()
        if body is not None:
            self._sync_send(lambda: sync_room.report(room_id, self._sync_device(), body.get("ready", False), body.get("buffering", False), body.get("drift_ms", 0)))

    def _route_sync_command(self, room_id):
        if not self._sync_host_guard():
            return
        body = self._sync_body()
        if body is not None:
            self._sync_send(lambda: sync_room.command(room_id, self._sync_device(), body.get("action", ""), body.get("position_ms", 0)))

    def _route_sync_close(self, room_id):
        if self._sync_host_guard():
            self._sync_send(lambda: sync_room.close(room_id, self._sync_device()))
