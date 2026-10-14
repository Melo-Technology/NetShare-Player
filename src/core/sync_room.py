"""Ephemeral LAN playback synchronization rooms with bounded membership."""

from __future__ import annotations

import secrets
import hashlib
import hmac
import threading
import time

import src.state as state


MAX_SYNC_MEMBERS = 6
MAX_SYNC_ROOMS = 16
ROOM_TTL_SECONDS = 4 * 60 * 60
_lock = threading.RLock()
_rooms: dict[str, dict] = {}


class SyncRoomError(ValueError):
    pass


def _notify(room: dict, event: str, payload: dict | None = None) -> None:
    manager = state._ws_manager
    if manager:
        manager.send_to_devices_threadsafe(
            list(room["members"]),
            {"type": "sync_room_updated", "event": event, "room_id": room["id"], **(payload or {})},
        )


def create(host_id: str, media_id: str, media_type: str) -> dict:
    if media_type not in ("audio", "video") or not isinstance(media_id, str) or not media_id.startswith("/"):
        raise SyncRoomError("Invalid direct-play media")
    with _lock:
        _cleanup()
        if len(_rooms) >= MAX_SYNC_ROOMS:
            raise SyncRoomError("Room limit reached")
        room_id = secrets.token_urlsafe(12)
        room = {
            "id": room_id,
            "join_code": f"{secrets.randbelow(1_000_000):06d}",
            "host_id": host_id,
            "media_id": media_id,
            "media_type": media_type,
            "members": {host_id: {"ready": True, "buffering": False, "drift_ms": 0}},
            "state": {"playing": False, "position_ms": 0, "sequence": 0, "execute_at": None},
            "updated_at": time.time(),
        }
        _rooms[room_id] = room
        return snapshot(room_id, host_id)


def join(device_id: str, code: str, media_id: str) -> dict:
    if not device_id:
        raise SyncRoomError("Device identity required")
    with _lock:
        room = next((value for value in _rooms.values() if value["join_code"] == str(code)), None)
        if room is None:
            raise SyncRoomError("Room not found")
        if media_id != room["media_id"]:
            raise SyncRoomError("Direct-play media mismatch")
        if len(room["members"]) >= MAX_SYNC_MEMBERS and device_id not in room["members"]:
            raise SyncRoomError("Room is full")
        ticket = secrets.token_urlsafe(32)
        room["members"][device_id] = {
            "ready": False,
            "buffering": True,
            "drift_ms": 0,
            "ticket_hash": _ticket_hash(ticket),
        }
        room["updated_at"] = time.time()
        _notify(room, "member_joined")
        return {**snapshot(room["id"], device_id), "room_ticket": ticket}


def verify_member_ticket(room_id: str, device_id: str, ticket: str) -> bool:
    """Validate the short-lived authority issued by this room's join code."""
    if not ticket:
        return False
    with _lock:
        room = _rooms.get(room_id)
        member = room["members"].get(device_id) if room else None
        expected = str(member.get("ticket_hash", "")) if member else ""
        return bool(expected and hmac.compare_digest(expected, _ticket_hash(ticket)))


def report(room_id: str, device_id: str, ready: bool, buffering: bool, drift_ms: int = 0) -> dict:
    with _lock:
        room = _member_room(room_id, device_id)
        room["members"][device_id] = {
            "ready": bool(ready),
            "buffering": bool(buffering),
            "drift_ms": max(-10_000, min(int(drift_ms), 10_000)),
        }
        room["updated_at"] = time.time()
        _notify(room, "member_status")
        return snapshot(room_id, device_id)


def command(room_id: str, host_id: str, action: str, position_ms: int) -> dict:
    with _lock:
        room = _member_room(room_id, host_id)
        if room["host_id"] != host_id:
            raise SyncRoomError("Host permission required")
        if action not in ("play", "pause", "seek"):
            raise SyncRoomError("Invalid playback command")
        room["state"]["sequence"] += 1
        room["state"]["playing"] = action == "play" or (action == "seek" and room["state"]["playing"])
        if action == "pause":
            room["state"]["playing"] = False
        room["state"]["position_ms"] = max(0, int(position_ms))
        room["state"]["execute_at"] = time.time() + 0.35
        room["updated_at"] = time.time()
        _notify(room, "playback_command", {"command": dict(room["state"])})
        return snapshot(room_id, host_id)


def snapshot(room_id: str, device_id: str) -> dict:
    with _lock:
        room = _member_room(room_id, device_id)
        return {
            "room_id": room["id"],
            "join_code": room["join_code"] if device_id == room["host_id"] else None,
            "host_id": room["host_id"],
            "is_host": device_id == room["host_id"],
            "media_id": room["media_id"],
            "media_type": room["media_type"],
            "members": [
                {"device_id": key, **{field: value for field, value in member.items() if field != "ticket_hash"}}
                for key, member in room["members"].items()
            ],
            "state": dict(room["state"]),
            "server_time": time.time(),
        }


def close(room_id: str, host_id: str) -> dict:
    with _lock:
        room = _member_room(room_id, host_id)
        if room["host_id"] != host_id:
            raise SyncRoomError("Host permission required")
        _rooms.pop(room_id, None)
        _notify(room, "closed")
        return {"closed": True}


def _member_room(room_id: str, device_id: str) -> dict:
    room = _rooms.get(room_id)
    if room is None:
        raise SyncRoomError("Room not found")
    if device_id not in room["members"]:
        raise SyncRoomError("Room membership required")
    return room


def _ticket_hash(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def _cleanup() -> None:
    cutoff = time.time() - ROOM_TTL_SECONDS
    for room_id in [key for key, value in _rooms.items() if value["updated_at"] < cutoff]:
        _rooms.pop(room_id, None)


def reset_for_tests() -> None:
    with _lock:
        _rooms.clear()
