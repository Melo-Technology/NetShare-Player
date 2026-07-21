"""Marker-based hidden folders whose status survives renames and moves."""

from pathlib import Path

HIDDEN_MARKER_FILENAME = ".netshare_hidden"


def mark_hidden(folder: Path) -> bool:
    """Create the portable marker inside *folder*."""
    try:
        folder.mkdir(parents=True, exist_ok=True)
        marker = folder / HIDDEN_MARKER_FILENAME
        if not marker.exists():
            marker.write_text("NetShare hidden folder\n", encoding="utf-8")
        return True
    except OSError:
        return False


def is_hidden_folder(folder: Path) -> bool:
    try:
        return folder.is_dir() and (folder / HIDDEN_MARKER_FILENAME).is_file()
    except OSError:
        return False


def is_inside_hidden_folder(path: Path, root: Path) -> bool:
    """Return True when path is, or belongs to, a marker-hidden folder."""
    try:
        current = path if path.is_dir() else path.parent
        root = root.resolve()
        current = current.resolve()
        current.relative_to(root)
        while current != root:
            if is_hidden_folder(current):
                return True
            current = current.parent
    except (OSError, ValueError):
        return False
    return False
