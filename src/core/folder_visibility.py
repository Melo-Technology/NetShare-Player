"""Shared Manage Folders operations used by both HTTP and desktop UI."""

import json

import src.state as state
from src.core.content_policy import is_config_hidden
from src.core.hidden_folders import is_hidden_folder
from src.core.share_tickets import share_ticket_store
from src.core.shared_paths import parse_shared_path, public_shared_path, resolve_shared_path


def folder_tree() -> dict:
    """Return shared roots without recursively scanning their descendants."""
    items = []
    for shared_root in state.SHARED_ROOTS:
        root_path = public_shared_path(shared_root.slot, "/")
        if len(state.SHARED_ROOTS) > 1 and not root_path.endswith("/"):
            root_path += "/"
        items.append({
            "slot": shared_root.slot,
            "name": shared_root.name,
            "path": root_path,
            "hidden": False,
            "directly_hidden": False,
            "has_children": _has_manageable_child(shared_root.path),
            "children": [],
        })
    hidden = [
        {
            "slot": slot,
            "path": public_shared_path(slot, path),
            "name": path.rstrip("/").rsplit("/", 1)[-1],
        }
        for slot, paths in state.HIDDEN_PATHS.items()
        for path in paths
        if state.root_for_slot(slot) is not None
    ]
    return {"items": items, "hidden": hidden}


def folder_children(requested: str) -> list[dict]:
    """Return one direct folder level for lazy expansion in Server/Player."""
    parsed = parse_shared_path(requested)
    resolved = resolve_shared_path(requested) if parsed is not None else None
    if parsed is None or resolved is None or not resolved.path.is_dir():
        raise FileNotFoundError("Folder not found")
    slot, _relative = parsed
    return _folder_children(slot, resolved.root, resolved.path)


def _folder_children(slot, root, directory):
    children = []
    try:
        entries = sorted(directory.iterdir(), key=lambda value: value.name.casefold())
    except (OSError, PermissionError):
        return children
    for entry in entries:
        if not entry.is_dir() or entry.name.startswith(".") or is_hidden_folder(entry):
            continue
        relative = "/" + entry.relative_to(root).as_posix()
        children.append({
            "slot": slot,
            "name": entry.name,
            "path": public_shared_path(slot, relative),
            "hidden": is_config_hidden(slot, relative),
            "directly_hidden": relative in state.HIDDEN_PATHS.get(slot, ()),
            "has_children": _has_manageable_child(entry),
            "children": [],
        })
    return children


def _has_manageable_child(directory) -> bool:
    try:
        return any(
            entry.is_dir() and not entry.name.startswith(".") and not is_hidden_folder(entry)
            for entry in directory.iterdir()
        )
    except (OSError, PermissionError):
        return False


def set_folder_visibility(requested: str, hidden: bool) -> dict:
    """Change one folder globally and perform all security side effects."""
    parsed = parse_shared_path(requested)
    resolved = resolve_shared_path(requested) if parsed is not None else None
    if parsed is None or resolved is None or not resolved.path.is_dir():
        raise FileNotFoundError("Folder not found")
    slot, relative = parsed
    if not str(relative).strip("/"):
        raise ValueError("A shared root cannot be hidden")
    clean = "/" + str(relative).replace("\\", "/").strip("/")
    changed = state.set_hidden_path(slot, clean, hidden)
    revoked = share_ticket_store.revoke_paths(slot, clean) if hidden else []
    payload = {
        "type": "folder_visibility_changed",
        "slot": slot,
        "path": public_shared_path(slot, clean),
        "hidden": bool(hidden),
    }
    if state._ws_manager:
        state._ws_manager.broadcast_threadsafe(json.dumps(payload, ensure_ascii=False))
    return {"ok": True, "changed": changed, "revoked_ticket_ids": revoked, **payload}
