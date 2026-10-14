"""Stable identities for the two local folders exposed by one server."""

from dataclasses import dataclass
from pathlib import Path


PRIMARY_ROOT_SLOT = "slot-1"
SECONDARY_ROOT_SLOT = "slot-2"
ROOT_SLOTS = (PRIMARY_ROOT_SLOT, SECONDARY_ROOT_SLOT)


class SharedRootConflictError(ValueError):
    def __init__(self, selected: Path, existing: Path):
        self.selected = Path(selected)
        self.existing = Path(existing)
        super().__init__(f"{self.selected} overlaps shared root {self.existing}")


@dataclass(frozen=True)
class SharedRoot:
    slot: str
    path: Path

    def __post_init__(self):
        if self.slot not in ROOT_SLOTS:
            raise ValueError("unknown shared-root slot")
        object.__setattr__(self, "path", Path(self.path).resolve())

    @property
    def name(self) -> str:
        return self.path.name or str(self.path)

    def to_json(self) -> dict:
        return {"slot": self.slot, "path": str(self.path)}


def normalize_shared_roots(paths) -> tuple[SharedRoot, ...]:
    roots = []
    seen = set()
    for slot, raw_path in zip(ROOT_SLOTS, paths):
        if not raw_path:
            continue
        root = SharedRoot(slot, Path(raw_path))
        key = str(root.path).casefold()
        for existing in roots:
            root_inside_existing = existing_inside_root = False
            try:
                root.path.relative_to(existing.path)
                root_inside_existing = True
            except ValueError:
                pass
            try:
                existing.path.relative_to(root.path)
                existing_inside_root = True
            except ValueError:
                pass
            if root_inside_existing or existing_inside_root:
                raise SharedRootConflictError(root.path, existing.path)
        seen.add(key)
        roots.append(root)
    return tuple(roots)
