"""Shared filesystem visibility rules for local and clustered catalogues."""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from src.core import unlock_codes
from src.core.hidden_folders import (
    HIDDEN_MARKER_FILENAME,
    is_hidden_folder,
    is_inside_hidden_folder,
)
from src.core.shared_roots import PRIMARY_ROOT_SLOT

INBOX_SLOT = "inbox"


@dataclass(frozen=True)
class ResolvedContentPath:
    """A resolved path whose logical storage identity is never inferred."""

    slot: str
    root: Path
    relative: str
    path: Path

# ---------------------------------------------------------------------------
# OS / filesystem / NAS internal entries that must never surface in any
# catalogue, regardless of which OS the server itself runs on — an external
# drive or network share can carry Windows/macOS/NAS artifacts even when
# mounted on a different OS.
# ---------------------------------------------------------------------------

_SYSTEM_FOLDER_NAMES = frozenset(name.casefold() for name in (
    # --- Windows ---
    "$Recycle.Bin",
    "System Volume Information",
    "RECYCLER",
    "RECYCLED",
    "MSOCache",
    "Config.Msi",
    "$WinREAgent",
    "$WINDOWS.~BT",
    "$WINDOWS.~WS",
    "$SysReset",
    "Recovery",
    "PerfLogs",
    "Documents and Settings",   # legacy junction on modern Windows
    "found.000",                # chkdsk-recovered files on FAT volumes

    # --- macOS ---
    ".Trashes",
    ".Spotlight-V100",
    ".fseventsd",
    ".DocumentRevisions-V100",
    ".TemporaryItems",
    ".apDisk",
    ".com.apple.timemachine.donotpresent",
    ".PKInstallSandboxManager",
    ".PKInstallSandboxManager-SystemSoftware",
    ".MobileBackups",
    ".MobileBackups.trash",
    ".AppleDB",
    ".AppleDesktop",
    ".AppleDouble",
    "Network Trash Folder",
    "Temporary Items",

    # --- Linux / general filesystem internals ---
    "lost+found",
    ".Trash",                   # freedesktop.org top-level trash (removable media)
    ".snapshots",                # Btrfs / Synology snapshot dir

    # --- NAS (Synology / QNAP) junk commonly seen on network shares ---
    "@eaDir",                    # Synology thumbnail/metadata cache, appears in every folder
    "@tmp",
    "#recycle",                  # Synology/QNAP network recycle bin
    ".@__thumb",                 # QNAP thumbnail cache
    ".streams",                  # QNAP extended-attribute stream store
    ".SynologyWorkingDirectory",
))

_SYSTEM_FILE_NAMES = frozenset(name.casefold() for name in (
    # --- Windows ---
    "desktop.ini",
    "Thumbs.db",
    "ehthumbs.db",
    "ehthumbs_vista.db",
    "IconCache.db",
    "ntuser.dat",
    "ntuser.dat.log",
    "ntuser.dat.log1",
    "ntuser.dat.log2",
    "ntuser.ini",
    "hiberfil.sys",
    "pagefile.sys",
    "swapfile.sys",
    "bootmgr",
    "bootnxt",
    "bootsect.bak",
    "DumpStack.log",
    "DumpStack.log.cfg",

    # --- macOS ---
    ".DS_Store",                 # already caught by leading-dot rule, kept for clarity
    ".localized",
    ".metadata_never_index",
    ".metadata_never_index_unless_rootfs",
    ".com.apple.timemachine.supported",
    ".VolumeIcon.icns",
    ".fseventsd",                # can appear as a file marker on some volumes too
    "Icon\r",                    # custom folder icon marker (literal trailing CR in the name)

    # --- Linux / general ---
    ".directory",                 # KDE/Dolphin per-folder metadata

    # --- NetShare configuration / internal state ---
    "unlock_codes.db",            # Premium folder access codes database
    "unlock_codes.db-journal",    # SQLite WAL journal file for unlock_codes.db
))

# Filename *patterns* (prefix/suffix) rather than exact names.
_SYSTEM_FOLDER_PREFIXES = (
    ".Trash-",         # per-uid Linux trash, e.g. .Trash-1000
)
_SYSTEM_FILE_PREFIXES = (
    "._",              # macOS AppleDouble resource-fork shadow files
    "~$",              # Microsoft Office lock/temp files, e.g. ~$report.docx
)


def _is_system_entry(entry: Path) -> bool:
    name_cf = entry.name.casefold()
    if entry.is_dir():
        if name_cf in _SYSTEM_FOLDER_NAMES:
            return True
        return any(entry.name.startswith(prefix) for prefix in _SYSTEM_FOLDER_PREFIXES)
    if name_cf in _SYSTEM_FILE_NAMES:
        return True
    return any(entry.name.startswith(prefix) for prefix in _SYSTEM_FILE_PREFIXES)


def normalize_relative_path(requested: str) -> str:
    clean = unquote(str(requested or "")).replace("\\", "/")
    clean = "/" + clean.strip("/")
    return clean if clean != "//" else "/"


def is_config_hidden(slot: str, requested: str) -> bool:
    """True for a configured hidden folder and every descendant."""
    import src.state as state
    clean = normalize_relative_path(requested)
    return any(
        clean == hidden or clean.startswith(hidden + "/")
        for hidden in state.HIDDEN_PATHS.get(slot, ())
    )


def profile_allows_path(
    slot: str, requested: str, allowed_paths: tuple[tuple[str, str], ...] | None,
) -> bool:
    """Apply an optional guest profile without weakening hidden-path checks."""
    if allowed_paths is None:
        return True
    clean = normalize_relative_path(requested)
    return any(
        slot == allowed_slot
        and (
            clean == allowed
            or clean.startswith(allowed.rstrip("/") + "/")
            or allowed.startswith(clean.rstrip("/") + "/")
        )
        for allowed_slot, allowed in allowed_paths
    )


def visible_shared_entry(
    entry: Path, *, root: Path | None = None, slot: str = PRIMARY_ROOT_SLOT,
    allowed_paths: tuple[tuple[str, str], ...] | None = None,
) -> bool:
    """Keep internal, OS/NAS system, and hidden entries out of every NetShare catalogue."""
    system_visible = not (
        entry.name.startswith(".")
        or entry.name in (unlock_codes.MARKER_FILENAME, HIDDEN_MARKER_FILENAME)
        or (entry.is_dir() and is_hidden_folder(entry))
        or _is_system_entry(entry)
    )
    if not system_visible or root is None:
        return system_visible
    try:
        relative = "/" + str(entry.resolve().relative_to(root.resolve())).replace("\\", "/")
    except (OSError, ValueError):
        return False
    return not is_config_hidden(slot, relative) and profile_allows_path(
        slot, relative, allowed_paths,
    )


def resolve_under_shared_root(root: Path, requested: str) -> Path | None:
    """Resolve an untrusted virtual path without allowing root escape."""
    if not isinstance(requested, str):
        return None
    clean = unquote(requested).lstrip("/\\")
    resolved = (Path(root) / clean).resolve()
    try:
        resolved.relative_to(Path(root).resolve())
        return resolved
    except ValueError:
        return None


def resolve_visible_shared_path(
    root: Path, requested: str, *, require_file: bool = False,
    slot: str = PRIMARY_ROOT_SLOT,
    allowed_paths: tuple[tuple[str, str], ...] | None = None,
) -> Path | None:
    """Resolve a public path and enforce the catalogue visibility boundary."""
    target = resolve_under_shared_root(root, requested)
    if target is None or not target.exists():
        return None
    if require_file and not target.is_file():
        return None
    try:
        relative = target.relative_to(Path(root).resolve())
    except ValueError:
        return None
    if any(
        part.startswith(".")
        or part in (unlock_codes.MARKER_FILENAME, HIDDEN_MARKER_FILENAME)
        for part in relative.parts
    ):
        return None
    resolved_root = Path(root).resolve()
    for i in range(len(relative.parts)):
        segment = resolved_root.joinpath(*relative.parts[:i + 1])
        if _is_system_entry(segment):
            return None
    if is_inside_hidden_folder(target, resolved_root):
        return None
    if is_config_hidden(slot, requested):
        return None
    if not profile_allows_path(slot, requested, allowed_paths):
        return None
    return target


def resolve_content_path(
    slot: str, root: Path, requested: str, *, visible: bool = False,
    require_file: bool = False,
) -> ResolvedContentPath | None:
    """Resolve one explicitly identified storage root through this policy."""
    clean = normalize_relative_path(requested)
    resolver = resolve_visible_shared_path if visible else resolve_under_shared_root
    target = (
        resolver(root, clean, require_file=require_file, slot=slot)
        if visible
        else resolver(root, clean)
    )
    if target is None:
        return None
    return ResolvedContentPath(slot, Path(root).resolve(), clean, target)


def resolve_inbox_path(
    inbox_root: Path, requested: str, *, visible: bool = False,
    require_file: bool = False,
) -> ResolvedContentPath | None:
    return resolve_content_path(
        INBOX_SLOT, inbox_root, requested,
        visible=visible, require_file=require_file,
    )
