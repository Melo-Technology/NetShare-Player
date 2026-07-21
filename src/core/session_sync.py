"""Small persistent trusted-device session groups for cross-device resume."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from pathlib import Path

import src.state as state
from src.i18n import t

STORE_PATH = state._CONFIG_DIR / "session_groups.json"
INVITE_TTL_SECONDS = 10 * 60
STATE_TTL_SECONDS = 6 * 60 * 60
MAX_DEVICES = 10
_LOCK = threading.RLock()


def _load() -> dict:
    try:
        data = json.loads(STORE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"groups": {}}
    except (OSError, json.JSONDecodeError):
        return {"groups": {}}


_DATA = _load()
_DATA.setdefault("groups", {})


def _save():
    state._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(_DATA, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(STORE_PATH)


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
                members.append({
                    "device_id": device_id,
                    "label": _device_label(device_id, device_label),
                    "joined_at": now,
                })
                _save()
            elif device_label and existing["label"] != _device_label(device_id, device_label):
                existing["label"] = _device_label(device_id, device_label)
                _save()
            return {
                "status": "ok", "session_group_id": group_id,
                "group_name": group.get("name", "Mes appareils"),
            }
    return {"status": "invalid_or_expired_invite"}


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
    with _LOCK:
        group = _authorized(group_id, device_id)
        if group is None:
            return {"status": "forbidden"}
        group["members"] = [
            member for member in _normalize_members(group)
            if member["device_id"] != device_id
        ]
        deleted = not group["members"]
        if deleted:
            _DATA["groups"].pop(group_id, None)
        elif (group.get("state") or {}).get("source_device_id") == device_id:
            group["state"] = None
        _save()
        return {"status": "ok", "group_deleted": deleted}


def remove_member(group_id: str, requester_id: str, target_device_id: str) -> dict:
    if requester_id == target_device_id:
        return {"status": "use_leave"}
    with _LOCK:
        group = _authorized(group_id, requester_id)
        if group is None:
            return {"status": "forbidden"}
        members = _normalize_members(group)
        if not any(member["device_id"] == target_device_id for member in members):
            return {"status": "not_found"}
        group["members"] = [
            member for member in members if member["device_id"] != target_device_id
        ]
        if (group.get("state") or {}).get("source_device_id") == target_device_id:
            group["state"] = None
        _save()
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

