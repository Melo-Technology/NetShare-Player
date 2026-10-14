"""Central mapping from opaque multiroot paths to authorized local roots."""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

import src.state as state
from src.core.content_policy import resolve_under_shared_root, resolve_visible_shared_path
from src.core.shared_roots import PRIMARY_ROOT_SLOT, ROOT_SLOTS


VIRTUAL_ROOT_PREFIX = "/@shares/"


@dataclass(frozen=True)
class ResolvedSharedPath:
    slot: str
    root: Path
    relative: str
    path: Path

    @property
    def virtual_path(self) -> str:
        return public_shared_path(self.slot, self.relative)


def encode_shared_path(slot: str, relative: str) -> str:
    if slot not in ROOT_SLOTS:
        raise ValueError("unknown shared-root slot")
    clean = str(relative or "").replace("\\", "/").lstrip("/")
    return f"{VIRTUAL_ROOT_PREFIX}{slot}/{clean}".rstrip("/") or "/"


def public_shared_path(slot: str, relative: str) -> str:
    """Keep the historical wire path for a one-root server."""
    clean = "/" + str(relative or "").replace("\\", "/").lstrip("/")
    return encode_shared_path(slot, clean) if len(state.SHARED_ROOTS) > 1 else clean


def parse_shared_path(requested: str, *, default_slot: str = PRIMARY_ROOT_SLOT):
    if not isinstance(requested, str):
        return None
    decoded = unquote(requested)
    if not decoded.startswith(VIRTUAL_ROOT_PREFIX):
        return default_slot, decoded
    remainder = decoded[len(VIRTUAL_ROOT_PREFIX):]
    slot, separator, relative = remainder.partition("/")
    if slot not in ROOT_SLOTS or not separator:
        return None
    return slot, relative


def resolve_shared_path(
    requested: str,
    *,
    default_slot: str = PRIMARY_ROOT_SLOT,
    visible: bool = False,
    require_file: bool = False,
    allowed_paths: tuple[tuple[str, str], ...] | None = None,
) -> ResolvedSharedPath | None:
    parsed = parse_shared_path(requested, default_slot=default_slot)
    if parsed is None:
        return None
    slot, relative = parsed
    root = state.root_for_slot(slot)
    if root is None:
        return None
    resolver = resolve_visible_shared_path if visible else resolve_under_shared_root
    target = (
        resolver(
            root, relative, require_file=require_file, slot=slot,
            allowed_paths=allowed_paths,
        )
        if visible
        else resolver(root, relative)
    )
    if target is None:
        return None
    return ResolvedSharedPath(slot, root, relative, target)
