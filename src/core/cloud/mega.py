"""
Mega provider -- wraps the `megatools` CLI (https://megotools.megous.com).

Validated approach (per discussion): megatools-if-available, otherwise this
provider reports itself unavailable with a clear, actionable message rather
than either crashing or silently no-op'ing. No third-party Mega Python
library is used -- those wrap Mega's undocumented protocol directly and
tend to break on API changes; megatools is the actively maintained, widely
packaged option and degrades cleanly to "feature disabled" when absent.

IMPORTANT LIMITATION, flagged rather than hidden: Mega has no public REST
API for byte-range downloads, and megatools does not expose partial-range
streaming over stdout -- `megatools get`/`megadl` always fetch the whole
file to disk. This is the one provider that cannot satisfy the "stream in
a bridge, no local copy" requirement from the spec. The pragmatic
compromise implemented here: download once into a bounded local cache
(state._CONFIG_DIR/"mega_cache"), then serve *that* cached file with full
Range support like any local file -- so the first playback of a given file
has to buffer completely before it can seek, but every request after that
(including seeking within the same playback) is instant. The cache is
capped by total size with LRU-ish eviction (oldest mtime first).

No OAuth: Mega authenticates via account email/password passed to each CLI
invocation. These are stored via TokenStore like any other provider's
tokens, so they get the same encryption-if-available treatment.
"""

import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterator

import src.state as state
from src.core.cloud.base import CloudProvider, CloudProviderError, StreamResult
from src.deps import HAS_MEGATOOLS, MEGATOOLS_BIN, MEGATOOLS_DOWNLOAD_URL

_CACHE_DIR = state._CONFIG_DIR / "mega_cache"
_MAX_CACHE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB, adjust from Settings later if needed
_DOWNLOAD_LOCK = threading.Lock()  # serialize downloads; megatools has no async API


def is_available() -> bool:
    return HAS_MEGATOOLS


def unavailable_message() -> str:
    return (
        f"Mega non disponible -- installez megatools ({MEGATOOLS_DOWNLOAD_URL}) "
        "puis relancez NetShare Server."
    )


def connect(email: str, password: str, label: str = "") -> dict:
    """Validate credentials once (via `megatools df`, a cheap read-only call)
    before storing them."""
    if not HAS_MEGATOOLS:
        raise CloudProviderError("missing_dependency", unavailable_message())
    try:
        proc = subprocess.run(
            [MEGATOOLS_BIN, "df", "--username", email, "--password", password],
            capture_output=True, text=True, timeout=20,
        )
    except Exception as e:
        raise CloudProviderError("provider_error", str(e))
    if proc.returncode != 0:
        raise CloudProviderError(
            "auth_failed", (proc.stderr or "").strip() or "Invalid Mega credentials"
        )
    return {"email": email, "password": password, "label": label or email}


# `megatools ls -l` output parsing.
#
# NOTE for Dani: I don't have megatools installed in this sandbox to verify
# the exact column format against a live account, so this parser is written
# defensively -- it falls back to name-only entries (no size/date) rather
# than raising if a line doesn't match the expected shape. Please sanity
# check `megatools ls -l /Root` against a real folder before relying on
# sizes/dates in the GUI; the plain `ls` path-listing this falls back to is
# the documented, stable part of the CLI.
_LS_L_PATTERN = re.compile(
    r"^(?P<perms>[dfl-])\S*\s+(?P<size>\d+|\s*-\s*)\s+"
    r"(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<path>/.+)$"
)


def _parse_ls_output(raw: str, parent_path: str) -> list[dict]:
    """Pure function, unit-testable without the real binary: turn `megatools
    ls -l` stdout into our common file-entry schema."""
    entries: dict[str, dict] = {}
    for line in raw.splitlines():
        line = line.rstrip()
        if not line:
            continue
        match = _LS_L_PATTERN.match(line)
        if not match:
            continue
        path = match.group("path").strip()
        if path.rstrip("/") == parent_path.rstrip("/"):
            continue  # the parent folder itself is often echoed as the first line
        name = path.rstrip("/").rsplit("/", 1)[-1]
        is_dir = match.group("perms") == "d"
        size_raw = match.group("size").strip()
        size = None if is_dir or not size_raw.isdigit() else int(size_raw)
        entries[path] = {
            "id": path,
            "name": name,
            "is_dir": is_dir,
            "size": size,
            "modified": match.group("date"),
            "mime_type": "",
        }
    return list(entries.values())


class MegaProvider(CloudProvider):
    provider_id = "mega"
    supports_range_streaming = False  # see module docstring

    def _creds(self) -> tuple[str, str]:
        return self._token_data["email"], self._token_data["password"]

    def _run(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        if not HAS_MEGATOOLS:
            raise CloudProviderError("missing_dependency", unavailable_message())
        email, password = self._creds()
        return subprocess.run(
            [MEGATOOLS_BIN, *args, "--username", email, "--password", password],
            capture_output=True, text=True, timeout=timeout,
        )

    def list_files(self, folder_id: str = "root") -> list[dict]:
        path = "/Root" if folder_id in ("root", "", "/") else folder_id
        proc = self._run("ls", "-l", path, timeout=30)
        if proc.returncode != 0:
            stderr = (proc.stderr or "").lower()
            if "login" in stderr or "password" in stderr or "auth" in stderr:
                raise CloudProviderError("auth_expired", "Mega login failed; reconnect this account.")
            raise CloudProviderError("provider_error", (proc.stderr or "").strip()[:300])
        entries = _parse_ls_output(proc.stdout, path)
        if entries:
            return entries
        # Defensive fallback: `-l` parsing found nothing usable (format
        # mismatch) -- fall back to the plain, stable `ls` (names only).
        proc2 = self._run("ls", path, timeout=30)
        if proc2.returncode != 0:
            return []
        out = []
        for line in proc2.stdout.splitlines():
            line = line.strip()
            if not line or line.rstrip("/") == path.rstrip("/"):
                continue
            name = line.rstrip("/").rsplit("/", 1)[-1]
            out.append({
                "id": line, "name": name, "is_dir": line.endswith("/"),
                "size": None, "modified": "", "mime_type": "",
            })
        return out

    # Local cache management

    @staticmethod
    def _cache_key(mega_path: str) -> str:
        import hashlib
        return hashlib.sha256(mega_path.encode("utf-8")).hexdigest()

    def _cached_path(self, mega_path: str) -> Path:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        return _CACHE_DIR / self._cache_key(mega_path)

    def _evict_if_needed(self, incoming_bytes: int):
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted(
            (p for p in _CACHE_DIR.iterdir() if p.is_file()),
            key=lambda p: p.stat().st_mtime,
        )
        total = sum(p.stat().st_size for p in files)
        i = 0
        while total + incoming_bytes > _MAX_CACHE_BYTES and i < len(files):
            try:
                total -= files[i].stat().st_size
                files[i].unlink(missing_ok=True)
            except OSError:
                pass
            i += 1

    def _ensure_downloaded(self, mega_path: str) -> Path:
        cached = self._cached_path(mega_path)
        if cached.exists() and cached.stat().st_size > 0:
            cached.touch()  # bump mtime for LRU-ish eviction
            return cached
        with _DOWNLOAD_LOCK:
            if cached.exists() and cached.stat().st_size > 0:
                return cached
            email, password = self._creds()
            tmp = cached.with_suffix(".part")
            proc = subprocess.run(
                [MEGATOOLS_BIN, "get", "--username", email, "--password", password,
                 "--path", str(tmp.parent), mega_path],
                capture_output=True, text=True, timeout=None,
            )
            if proc.returncode != 0 or not tmp.exists():
                raise CloudProviderError(
                    "provider_error",
                    (proc.stderr or "").strip()[:300] or "Mega download failed",
                )
            self._evict_if_needed(tmp.stat().st_size)
            tmp.replace(cached)
            return cached

    def stream_file(self, file_id: str, range_header: str | None) -> StreamResult:
        try:
            local_path = self._ensure_downloaded(file_id)
        except CloudProviderError as e:
            status = {"auth_expired": 401, "missing_dependency": 503}.get(e.code, 502)
            return StreamResult(status=status, headers={}, chunks=None, error=e.code)

        size = local_path.stat().st_size
        start, end = 0, size - 1
        status = 200
        if range_header and range_header.startswith("bytes="):
            try:
                rng = range_header.split("=", 1)[1].split("-")
                if rng[0]:
                    start = int(rng[0])
                if len(rng) > 1 and rng[1]:
                    end = int(rng[1])
                status = 206
            except ValueError:
                start, end, status = 0, size - 1, 200

        length = end - start + 1
        headers = {
            "Accept-Ranges": "bytes",
            "Content-Length": str(length),
        }
        if status == 206:
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"

        def _iter(chunk_size: int = 256 * 1024) -> Iterator[bytes]:
            with open(local_path, "rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(chunk_size, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    yield chunk

        return StreamResult(status=status, headers=headers, chunks=_iter())
