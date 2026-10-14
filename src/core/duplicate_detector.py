"""Progressive, read-only duplicate detection across explicit storage roots."""

from __future__ import annotations

import copy
import os
import threading
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from src.core.file_fingerprint import FileFingerprint, fingerprint_file


MAX_SCAN_ERRORS = 100


@dataclass(frozen=True)
class DuplicateScanRoot:
    root_slot: str
    path: Path


@dataclass(frozen=True)
class _Candidate:
    root_slot: str
    root: Path
    relative: str
    path: Path
    size: int


class DuplicateDetector:
    def __init__(
        self,
        *,
        fingerprinter: Callable[[Path], FileFingerprint] = fingerprint_file,
    ):
        self._fingerprinter = fingerprinter
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._state = self._initial_state()

    def start(self, roots: tuple[DuplicateScanRoot, ...]) -> bool:
        normalized = tuple(
            DuplicateScanRoot(root.root_slot, Path(root.path).resolve())
            for root in roots
        )
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._state = {
                **self._initial_state(), "status": "scanning",
                "phase": "enumerating",
            }
            self._thread = threading.Thread(
                target=self._run, args=(normalized,), daemon=True,
                name="netshare-duplicate-scan",
            )
            self._thread.start()
            return True

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._state)

    def wait(self, timeout: float = 5.0) -> bool:
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        return thread is None or not thread.is_alive()

    def _run(self, roots: tuple[DuplicateScanRoot, ...]) -> None:
        try:
            candidates = self._enumerate(roots)
            size_groups: dict[int, list[_Candidate]] = defaultdict(list)
            for candidate in candidates:
                size_groups[candidate.size].append(candidate)
            hash_candidates = [
                candidate
                for group in size_groups.values() if len(group) > 1
                for candidate in group
            ]
            self._update(
                phase="hashing", hash_candidates=len(hash_candidates),
            )
            fingerprints: dict[tuple[int, str], list[_Candidate]] = defaultdict(list)
            for candidate in hash_candidates:
                try:
                    fingerprint = self._fingerprinter(candidate.path)
                    if fingerprint.size != candidate.size:
                        raise RuntimeError("file size changed before hashing")
                    fingerprints[(fingerprint.size, fingerprint.digest)].append(candidate)
                except (OSError, RuntimeError, ValueError) as error:
                    self._error(candidate, error)
                finally:
                    self._increment("files_hashed")
            groups = []
            for (size, digest), occurrences in fingerprints.items():
                if len(occurrences) < 2:
                    continue
                groups.append({
                    "size": size, "algorithm": "sha256", "digest": digest,
                    "occurrences": [
                        {"root_slot": item.root_slot, "path": item.relative}
                        for item in sorted(
                            occurrences,
                            key=lambda value: (value.root_slot, value.relative.casefold()),
                        )
                    ],
                })
            groups.sort(key=lambda group: (-group["size"], group["digest"]))
            self._update(status="completed", phase="completed", groups=groups)
        except Exception as error:
            self._update(status="failed", phase="failed")
            self._error(None, error)

    def _enumerate(self, roots: tuple[DuplicateScanRoot, ...]) -> list[_Candidate]:
        candidates = []
        seen_physical = set()
        for scan_root in roots:
            if not scan_root.path.is_dir():
                self._error(None, OSError(f"scan root unavailable: {scan_root.root_slot}"))
                continue
            for directory, dirnames, filenames in os.walk(
                scan_root.path, followlinks=False,
            ):
                base = Path(directory)
                dirnames[:] = [
                    name for name in dirnames
                    if not name.startswith(".") and not (base / name).is_symlink()
                ]
                for filename in filenames:
                    if filename.startswith("."):
                        continue
                    path = base / filename
                    try:
                        if path.is_symlink() or not path.is_file():
                            continue
                        resolved = path.resolve()
                        physical_key = os.path.normcase(str(resolved))
                        if physical_key in seen_physical:
                            continue
                        stat = resolved.stat()
                        relative = "/" + resolved.relative_to(scan_root.path).as_posix()
                        seen_physical.add(physical_key)
                        candidates.append(_Candidate(
                            scan_root.root_slot, scan_root.path, relative,
                            resolved, stat.st_size,
                        ))
                        self._increment("files_discovered")
                    except (OSError, ValueError) as error:
                        self._error(None, error)
        return candidates

    def _increment(self, key: str) -> None:
        with self._lock:
            self._state[key] += 1

    def _update(self, **values) -> None:
        with self._lock:
            self._state.update(values)

    def _error(self, candidate: _Candidate | None, error: Exception) -> None:
        with self._lock:
            if len(self._state["errors"]) >= MAX_SCAN_ERRORS:
                return
            item = {"error": f"{type(error).__name__}: {error}"}
            if candidate is not None:
                item.update({
                    "root_slot": candidate.root_slot,
                    "path": candidate.relative,
                })
            self._state["errors"].append(item)

    @staticmethod
    def _initial_state() -> dict:
        return {
            "status": "idle", "phase": "idle",
            "files_discovered": 0, "hash_candidates": 0,
            "files_hashed": 0, "groups": [], "errors": [],
        }
