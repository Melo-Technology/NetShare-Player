"""Bounded, LAN-scoped collaborative audio queues."""

from __future__ import annotations

import secrets
import hashlib
import hmac
import threading
import time

import src.state as state


MAX_ROOMS = 16
MAX_MEMBERS = 12
MAX_QUEUE_ITEMS = 100
ROOM_TTL_SECONDS = 6 * 60 * 60

_lock = threading.RLock()
_rooms: dict[str, dict] = {}


class CollaborativeQueueError(ValueError):
    pass


def _emit(room: dict, action: str) -> None:
    manager = state._ws_manager
    if manager:
        manager.send_to_devices_threadsafe(
            list(room["members"]),
            {"type": "collaborative_queue_updated", "room_id": room["id"], "action": action},
        )


def _cleanup() -> None:
    cutoff = time.time() - ROOM_TTL_SECONDS
    for room_id in [key for key, room in _rooms.items() if room["updated_at"] < cutoff]:
        _rooms.pop(room_id, None)


def create_room(host_id: str, options: dict | None = None) -> dict:
    if not host_id:
        raise CollaborativeQueueError("Device identity required")
    opts = options if isinstance(options, dict) else {}
    with _lock:
        _cleanup()
        if len(_rooms) >= MAX_ROOMS:
            raise CollaborativeQueueError("Room limit reached")
        room_id = secrets.token_urlsafe(12)
        room = {
            "id": room_id,
            "join_code": f"{secrets.randbelow(1_000_000):06d}",
            "host_id": host_id,
            "members": {host_id: {"label": str(opts.get("host_label", ""))[:64], "blocked": False}},
            "queue": [],
            "allow_proposals": bool(opts.get("allow_proposals", True)),
            "allow_votes": bool(opts.get("allow_votes", True)),
            "max_per_member": max(1, min(int(opts.get("max_per_member", 5)), 20)),
            "locked": False,
            "updated_at": time.time(),
        }
        _rooms[room_id] = room
        return snapshot(room_id, host_id)


def join_room(device_id: str, code: str, label: str = "") -> dict:
    if not device_id:
        raise CollaborativeQueueError("Device identity required")
    with _lock:
        _cleanup()
        room = next((item for item in _rooms.values() if item["join_code"] == str(code)), None)
        if room is None:
            raise CollaborativeQueueError("Room not found")
        if len(room["members"]) >= MAX_MEMBERS and device_id not in room["members"]:
            raise CollaborativeQueueError("Participant limit reached")
        prior = room["members"].get(device_id)
        if prior and prior.get("blocked"):
            raise CollaborativeQueueError("Participant blocked")
        ticket = secrets.token_urlsafe(32)
        room["members"][device_id] = {
            "label": str(label)[:64],
            "blocked": False,
            "ticket_hash": _ticket_hash(ticket),
        }
        room["updated_at"] = time.time()
        _emit(room, "member_joined")
        return {**snapshot(room["id"], device_id), "room_ticket": ticket}


def verify_member_ticket(room_id: str, device_id: str, ticket: str) -> bool:
    """Validate a room-scoped participant ticket without granting server-wide trust."""
    if not ticket:
        return False
    with _lock:
        room = _rooms.get(room_id)
        member = room["members"].get(device_id) if room else None
        expected = str(member.get("ticket_hash", "")) if member else ""
        return bool(expected and hmac.compare_digest(expected, _ticket_hash(ticket)))


def snapshot(room_id: str, device_id: str) -> dict:
    with _lock:
        room = _room_for_member(room_id, device_id)
        queue = sorted(room["queue"], key=lambda item: (-len(item["votes"]), item["created_at"]))
        return {
            "room_id": room["id"],
            "join_code": room["join_code"] if device_id == room["host_id"] else None,
            "host_id": room["host_id"],
            "is_host": device_id == room["host_id"],
            "allow_proposals": room["allow_proposals"],
            "allow_votes": room["allow_votes"],
            "max_per_member": room["max_per_member"],
            "locked": room["locked"],
            "members": [
                {"device_id": key, **{field: value for field, value in member.items() if field != "ticket_hash"}}
                for key, member in room["members"].items()
            ],
            "queue": [{**item, "votes": len(item["votes"]), "voted": device_id in item["votes"]} for item in queue],
        }


def propose(room_id: str, device_id: str, media_id: str, title: str = "") -> dict:
    with _lock:
        room = _room_for_member(room_id, device_id)
        if room["locked"] or (device_id != room["host_id"] and not room["allow_proposals"]):
            raise CollaborativeQueueError("Proposals are closed")
        if not isinstance(media_id, str) or not media_id.startswith("/") or ".." in media_id.split("/"):
            raise CollaborativeQueueError("Invalid media path")
        if len(room["queue"]) >= MAX_QUEUE_ITEMS:
            raise CollaborativeQueueError("Queue limit reached")
        count = sum(item["proposer_id"] == device_id for item in room["queue"])
        if count >= room["max_per_member"]:
            raise CollaborativeQueueError("Proposal limit reached")
        item = {"id": secrets.token_urlsafe(9), "media_id": media_id, "title": str(title)[:256], "proposer_id": device_id, "votes": {device_id}, "created_at": time.time()}
        room["queue"].append(item)
        room["updated_at"] = time.time()
        _emit(room, "item_added")
        return snapshot(room_id, device_id)


def vote(room_id: str, device_id: str, item_id: str, enabled: bool) -> dict:
    with _lock:
        room = _room_for_member(room_id, device_id)
        if not room["allow_votes"]:
            raise CollaborativeQueueError("Voting is disabled")
        item = next((value for value in room["queue"] if value["id"] == item_id), None)
        if item is None:
            raise CollaborativeQueueError("Queue item not found")
        (item["votes"].add if enabled else item["votes"].discard)(device_id)
        room["updated_at"] = time.time()
        _emit(room, "vote_changed")
        return snapshot(room_id, device_id)


def host_action(room_id: str, host_id: str, action: str, target_id: str = "") -> dict:
    with _lock:
        room = _room_for_member(room_id, host_id)
        if room["host_id"] != host_id:
            raise CollaborativeQueueError("Host permission required")
        if action == "lock":
            room["locked"] = True
        elif action == "unlock":
            room["locked"] = False
        elif action == "remove_item":
            room["queue"] = [item for item in room["queue"] if item["id"] != target_id]
        elif action in ("remove_member", "block_member"):
            if target_id == host_id:
                raise CollaborativeQueueError("Host cannot be removed")
            if action == "block_member":
                room["members"].setdefault(target_id, {})["blocked"] = True
            else:
                room["members"].pop(target_id, None)
        elif action == "close":
            _rooms.pop(room_id, None)
            _emit(room, "closed")
            return {"closed": True}
        else:
            raise CollaborativeQueueError("Unknown room action")
        room["updated_at"] = time.time()
        _emit(room, action)
        return snapshot(room_id, host_id)


def _room_for_member(room_id: str, device_id: str) -> dict:
    room = _rooms.get(room_id)
    if room is None:
        raise CollaborativeQueueError("Room not found")
    member = room["members"].get(device_id)
    if member is None or member.get("blocked"):
        raise CollaborativeQueueError("Room membership required")
    return room


def _ticket_hash(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def reset_for_tests() -> None:
    with _lock:
        _rooms.clear()
