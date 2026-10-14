"""One-time, non-overwriting migration from legacy slot-1 receive folders."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from src.core.content_policy import resolve_inbox_path


MIGRATION_MARKER = ".legacy-migration-v1.json"


def migrate_legacy_inbox(
    inbox_root: Path, legacy_roots: tuple[Path, ...], *,
    log=lambda _message, _kind="info": None,
) -> dict:
    inbox_root = Path(inbox_root).resolve()
    marker = inbox_root / MIGRATION_MARKER
    if marker.exists():
        return {"status": "already_completed", "moved": 0, "failed": 0}
    inbox_root.mkdir(parents=True, exist_ok=True)
    moved = 0
    failures = []
    sources = []
    for legacy_root in legacy_roots:
        source_root = Path(legacy_root).resolve()
        if source_root == inbox_root or not source_root.is_dir():
            continue
        sources.append(str(source_root))
        try:
            files = sorted(path for path in source_root.rglob("*") if path.is_file())
        except OSError as error:
            failures.append({"source": str(source_root), "error": str(error)})
            continue
        for source in files:
            try:
                relative = source.relative_to(source_root)
                resolved = resolve_inbox_path(inbox_root, str(relative))
                if resolved is None:
                    raise OSError("invalid Inbox migration destination")
                target = _unique_path(resolved.path)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(source), str(target))
                moved += 1
            except OSError as error:
                failures.append({"source": str(source), "error": str(error)})
    result = {"status": "partial" if failures else "completed", "moved": moved,
              "failed": len(failures), "sources": sources, "failures": failures}
    if not failures:
        temporary = marker.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        os.replace(temporary, marker)
    log(
        f"INBOX migration {result['status']}: moved={moved}, failed={len(failures)}",
        "error" if failures else "ok",
    )
    for failure in failures:
        log(f"INBOX migration kept source: {failure['source']}: {failure['error']}", "error")
    return result


def _unique_path(target: Path) -> Path:
    if not target.exists():
        return target
    for index in range(1, 10_000):
        candidate = target.parent / f"{target.stem} ({index}){target.suffix}"
        if not candidate.exists():
            return candidate
    raise OSError("unable to allocate Inbox migration filename")
