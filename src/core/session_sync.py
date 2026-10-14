"""Small persistent trusted-device session groups for cross-device resume."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from pathlib import Path

import src.state as state
from src.i18n import t
from src.core.vault_storage import read_json, write_json

STORE_PATH = state._CONFIG_DIR / "session_groups.json"
INVITE_TTL_SECONDS = 10 * 60
STATE_TTL_SECONDS = 6 * 60 * 60
MAX_DEVICES = 10
MAX_RESUME_HISTORY = 100
MAX_PENDING_HANDOFFS = 32
HANDOFF_TTL_SECONDS = 2 * 60
SUPPORTED_MEDIA_TYPES = {"audio", "video", "document", "text", "pdf"}
_LOCK = threading.RLock()


def _load() -> dict:
    data = read_json(STORE_PATH, purpose="session-groups", default={"groups": {}})
    return data if isinstance(data, dict) else {"groups": {}}


_DATA = _load()
_DATA.setdefault("groups", {})


def _save():
    write_json(STORE_PATH, _DATA, purpose="session-groups", indent=2)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_invite() -> tuple[str, str]:
    code = secrets.token_urlsafe(18)
    return code, _hash(code)


def _device_label(device_id: str, label: str = "") -> str:
    clean = str(label or "").strip()
    if clean:
        return clean[:80]
    suffix = str(device_id)[-4:] or "----"
    return f"Appareil {suffix}"


def _normalize_members(group: dict) -> list[dict]:
    """Migrate v1 string members to labelled member records in memory."""
    normalized = []
    for member in group.get("members", []):
        if isinstance(member, str):
            normalized.append({
                "device_id": member,
                "label": _device_label(member),
                "joined_at": group.get("created_at", 0),
            })
        elif isinstance(member, dict) and member.get("device_id"):
            device_id = str(member["device_id"])
            normalized.append({
                "device_id": device_id,
                "label": _device_label(device_id, member.get("label", "")),
                "joined_at": float(member.get("joined_at", group.get("created_at", 0))),
            })
    group["members"] = normalized
    return normalized


def _find_member(group: dict, device_id: str) -> dict | None:
    return next(
        (member for member in _normalize_members(group) if member["device_id"] == device_id),
        None,
    )


def _notify_group(
    group_id: str,
    group_name: str,
    recipients,
    action: str,
    member: dict,
):
    if state._ws_manager:
        state._ws_manager.send_to_devices_threadsafe(recipients, {
            "type": "group_updated",
            "session_group_id": group_id,
            "group_name": group_name,
            "action": action,
            "device_id": member["device_id"],
            "device_name": member["label"],
        })


def create_group(device_id: str, name: str, device_label: str = "") -> dict:
    if not state.is_trusted_device(device_id):
        return {"status": "untrusted_device"}
    now = time.time()
    group_id = secrets.token_urlsafe(24)
    invite, invite_hash = _new_invite()
    with _LOCK:
        _DATA["groups"][group_id] = {
            "name": str(name or "").strip() or t("my_devices"),
            "members": [{
                "device_id": device_id,
                "label": _device_label(device_id, device_label),
                "joined_at": now,
            }],
            "created_at": now,
            "invite_hash": invite_hash,
            "invite_expires_at": now + INVITE_TTL_SECONDS,
            "state": None,
        }
        _save()
    return {
        "status": "ok", "session_group_id": group_id,
        "group_name": _DATA["groups"][group_id]["name"],
        "invite_code": invite, "invite_expires_at": now + INVITE_TTL_SECONDS,
    }


def join_group(device_id: str, invite_code: str, device_label: str = "") -> dict:
    if not state.is_trusted_device(device_id):
        return {"status": "untrusted_device"}
    now = time.time()
    invite_hash = _hash(str(invite_code or "").strip())
    notification = None
    with _LOCK:
        for group_id, group in _DATA["groups"].items():
            if group.get("invite_expires_at", 0) <= now:
                continue
            if not secrets.compare_digest(group.get("invite_hash", ""), invite_hash):
                continue
            members = _normalize_members(group)
            existing = next(
                (member for member in members if member["device_id"] == device_id),
                None,
            )
            if existing is None and len(members) >= MAX_DEVICES:
                return {"status": "group_full"}
            if existing is None:
                joined_member = {
                    "device_id": device_id,
                    "label": _device_label(device_id, device_label),
                    "joined_at": now,
                }
                members.append(joined_member)
                _save()
                notification = (
                    group_id,
                    group.get("name", t("my_devices")),
                    [member["device_id"] for member in members],
                    "member_joined",
                    joined_member,
                )
            elif device_label and existing["label"] != _device_label(device_id, device_label):
                existing["label"] = _device_label(device_id, device_label)
                _save()
            result = {
                "status": "ok", "session_group_id": group_id,
                "group_name": group.get("name", t("my_devices")),
            }
            break
        else:
            return {"status": "invalid_or_expired_invite"}
    if notification:
        _notify_group(*notification)
    return result


def _authorized(group_id: str, device_id: str) -> dict | None:
    if not state.is_trusted_device(device_id):
        return None
    group = _DATA["groups"].get(group_id)
    if not group or _find_member(group, device_id) is None:
        return None
    return group


def update_state(group_id: str, device_id: str, track_id: str, position_ms: int) -> dict:
    with _LOCK:
        group = _authorized(group_id, device_id)
        if group is None:
            return {"status": "forbidden"}
        now = time.time()
        group["state"] = {
            "track_id": str(track_id), "position_ms": max(0, int(position_ms)),
            "updated_at": now, "source_device_id": device_id,
            "expires_at": now + STATE_TTL_SECONDS,
            "source_device_label": _find_member(group, device_id)["label"],
        }
        _save()
        return {"status": "ok", "updated_at": now}


def update_resume(
    group_id: str,
    device_id: str,
    media_id: str,
    media_type: str,
    position: dict,
) -> dict:
    """Store one bounded multi-media resume point and notify group peers."""
    media_id = str(media_id).strip()
    media_type = str(media_type).strip().lower()
    if not media_id or len(media_id) > 2048 or media_type not in SUPPORTED_MEDIA_TYPES:
        return {"status": "invalid"}
    normalized_position = _normalize_position(media_type, position)
    if normalized_position is None:
        return {"status": "invalid"}
    notification = None
    with _LOCK:
        group = _authorized(group_id, device_id)
        if group is None:
            return {"status": "forbidden"}
        now = time.time()
        member = _find_member(group, device_id)
        entry = {
            "media_id": media_id,
            "media_type": media_type,
            "position": normalized_position,
            "updated_at": now,
            "expires_at": now + STATE_TTL_SECONDS,
            "source_device_id": device_id,
            "source_device_label": member["label"],
        }
        history = group.setdefault("resume_history", [])
        history[:] = [item for item in history if item.get("media_id") != media_id]
        history.insert(0, entry)
        del history[MAX_RESUME_HISTORY:]
        group["resume_state"] = entry
        _save()
        recipients = [item["device_id"] for item in _normalize_members(group) if item["device_id"] != device_id]
        notification = (recipients, entry)
    if state._ws_manager and notification[0]:
        state._ws_manager.send_to_devices_threadsafe(notification[0], {"type": "resume_updated", **notification[1]})
    return {"status": "ok", "updated_at": entry["updated_at"]}


def get_resume_history(group_id: str, device_id: str, offset: int = 0, limit: int = 20) -> dict:
    with _LOCK:
        group = _authorized(group_id, device_id)
        if group is None:
            return {"status": "forbidden"}
        now = time.time()
        history = [dict(item) for item in group.get("resume_history", []) if item.get("expires_at", 0) > now]
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(int(limit), 50))
        return {"status": "ok", "items": history[safe_offset:safe_offset + safe_limit], "total": len(history), "offset": safe_offset, "has_more": safe_offset + safe_limit < len(history)}


def request_handoff(group_id: str, source_id: str, target_id: str, media_id: str, media_type: str, position: dict) -> dict:
    normalized = _normalize_position(media_type, position)
    if normalized is None or not str(media_id).strip():
        return {"status": "invalid"}
    with _LOCK:
        group = _authorized(group_id, source_id)
        if group is None or _find_member(group, target_id) is None or target_id == source_id:
            return {"status": "forbidden"}
        pending = group.setdefault("pending_handoffs", {})
        _cleanup_handoffs(pending)
        if len(pending) >= MAX_PENDING_HANDOFFS:
            return {"status": "busy"}
        handoff_id = secrets.token_urlsafe(18)
        source = _find_member(group, source_id)
        record = {
            "handoff_id": handoff_id,
            "source_device_id": source_id,
            "source_device_label": source["label"],
            "target_device_id": target_id,
            "media_id": str(media_id),
            "media_type": str(media_type),
            "position": normalized,
            "expires_at": time.time() + HANDOFF_TTL_SECONDS,
        }
        pending[handoff_id] = record
        _save()
    if state._ws_manager:
        state._ws_manager.send_to_devices_threadsafe([target_id], {"type": "handoff_requested", **record})
    return {"status": "pending", "handoff_id": handoff_id, "expires_at": record["expires_at"]}


def respond_handoff(group_id: str, target_id: str, handoff_id: str, accepted: bool) -> dict:
    with _LOCK:
        group = _authorized(group_id, target_id)
        if group is None:
            return {"status": "forbidden"}
        pending = group.setdefault("pending_handoffs", {})
        _cleanup_handoffs(pending)
        record = pending.get(handoff_id)
        if record is None or record.get("target_device_id") != target_id:
            return {"status": "not_found"}
        pending.pop(handoff_id, None)
        _save()
    if state._ws_manager:
        state._ws_manager.send_to_devices_threadsafe([record["source_device_id"]], {"type": "handoff_response", "handoff_id": handoff_id, "accepted": bool(accepted), "target_device_id": target_id})
    return {"status": "ok", "accepted": bool(accepted), "handoff": record if accepted else None}


def _normalize_position(media_type: str, position: dict) -> dict | None:
    if not isinstance(position, dict):
        return None
    if media_type in ("audio", "video"):
        try:
            return {"milliseconds": max(0, int(position.get("milliseconds", 0)))}
        except (TypeError, ValueError):
            return None
    try:
        return {
            "page": max(0, int(position.get("page", 0))),
            "offset": max(0.0, min(1.0, float(position.get("offset", 0)))),
        }
    except (TypeError, ValueError):
        return None


def _cleanup_handoffs(pending: dict) -> None:
    now = time.time()
    for handoff_id in [key for key, value in pending.items() if value.get("expires_at", 0) <= now]:
        pending.pop(handoff_id, None)


def get_state(group_id: str, device_id: str) -> dict:
    with _LOCK:
        group = _authorized(group_id, device_id)
        if group is None:
            return {"status": "forbidden"}
        playback = group.get("state")
        if not playback or playback.get("expires_at", 0) <= time.time():
            return {"status": "ok", "group_name": group.get("name"), "state": None}
        return {"status": "ok", "group_name": group.get("name"), "state": dict(playback)}


def list_members(group_id: str, device_id: str) -> dict:
    with _LOCK:
        group = _authorized(group_id, device_id)
        if group is None:
            return {"status": "forbidden"}
        active_members = [
            dict(member) for member in _normalize_members(group)
            if state.is_trusted_device(member["device_id"])
        ]
        return {
            "status": "ok", "session_group_id": group_id,
            "group_name": group.get("name", t("my_devices")),
            "members": active_members,
        }


def leave_group(group_id: str, device_id: str) -> dict:
    notification = None
    with _LOCK:
        group = _authorized(group_id, device_id)
        if group is None:
            return {"status": "forbidden"}
        members = _normalize_members(group)
        leaving_member = _find_member(group, device_id)
        recipients = [member["device_id"] for member in members]
        group_name = group.get("name", t("my_devices"))
        group["members"] = [
            member for member in members
            if member["device_id"] != device_id
        ]
        deleted = not group["members"]
        if deleted:
            _DATA["groups"].pop(group_id, None)
        elif (group.get("state") or {}).get("source_device_id") == device_id:
            group["state"] = None
        _save()
        if leaving_member:
            notification = (
                group_id, group_name, recipients, "member_left", leaving_member
            )
    if notification:
        _notify_group(*notification)
    return {"status": "ok", "group_deleted": deleted}


def remove_member(group_id: str, requester_id: str, target_device_id: str) -> dict:
    if requester_id == target_device_id:
        return {"status": "use_leave"}
    notification = None
    with _LOCK:
        group = _authorized(group_id, requester_id)
        if group is None:
            return {"status": "forbidden"}
        members = _normalize_members(group)
        removed_member = next(
            (member for member in members if member["device_id"] == target_device_id),
            None,
        )
        if removed_member is None:
            return {"status": "not_found"}
        recipients = [member["device_id"] for member in members]
        group_name = group.get("name", t("my_devices"))
        group["members"] = [
            member for member in members if member["device_id"] != target_device_id
        ]
        if (group.get("state") or {}).get("source_device_id") == target_device_id:
            group["state"] = None
        _save()
        notification = (
            group_id, group_name, recipients, "member_removed", removed_member
        )
    _notify_group(*notification)
    return {"status": "ok"}


def renew_invite(group_id: str, device_id: str) -> dict:
    with _LOCK:
        group = _authorized(group_id, device_id)
        if group is None:
            return {"status": "forbidden"}
        invite, invite_hash = _new_invite()
        expires_at = time.time() + INVITE_TTL_SECONDS
        group["invite_hash"] = invite_hash
        group["invite_expires_at"] = expires_at
        _save()
        return {
            "status": "ok", "session_group_id": group_id,
            "invite_code": invite, "invite_expires_at": expires_at,
        }


def reset_for_tests(path: Path | None = None):
    """Test hook: clear process state and optionally redirect persistence."""
    global STORE_PATH, _DATA
    with _LOCK:
        if path is not None:
            STORE_PATH = path
        _DATA = {"groups": {}}
