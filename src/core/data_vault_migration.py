"""Automatic, resumable plaintext -> Data Vault migration for C5.1."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from src.core.data_vault import FILE_MAGIC, get_data_vault
from src.core.vault_storage import encode_jsonl_record, migrate_file_in_place

MIGRATION_VERSION = 1
ASYNC_FILE_THRESHOLD = 40
ASYNC_BYTE_THRESHOLD = 8 * 1024 * 1024


@dataclass
class MigrationSnapshot:
    state: str = "idle"
    total_files: int = 0
    completed_files: int = 0
    total_bytes: int = 0
    completed_bytes: int = 0
    current: str = ""
    error: str = ""


@dataclass(frozen=True)
class _Task:
    label: str
    path: Path
    size: int
    action: Callable[[], bool]


class DataVaultMigrationController:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._snapshot = MigrationSnapshot()
        self._thread: threading.Thread | None = None

    def snapshot(self) -> dict:
        with self._lock:
            return asdict(self._snapshot)

    def start_if_needed(self, *, force_sync: bool = False) -> dict:
        import src.state as state

        vault = get_data_vault(state._CONFIG_DIR)
        if not vault.configured or not vault.unlocked:
            return self.snapshot()
        if vault.migration_version >= MIGRATION_VERSION:
            with self._lock:
                self._snapshot = MigrationSnapshot(state="completed")
            return self.snapshot()
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return asdict(self._snapshot)

        # Move sensitive values out of plaintext server_config.json first.
        state._save_config()
        tasks = self._discover_tasks()
        total_bytes = sum(task.size for task in tasks)
        with self._lock:
            self._snapshot = MigrationSnapshot(
                state="running" if tasks else "completed",
                total_files=len(tasks),
                total_bytes=total_bytes,
            )
        if not tasks:
            vault.mark_migration_complete(MIGRATION_VERSION)
            return self.snapshot()

        run_async = not force_sync and (
            len(tasks) >= ASYNC_FILE_THRESHOLD or total_bytes >= ASYNC_BYTE_THRESHOLD
        )
        if run_async:
            thread = threading.Thread(
                target=self._run,
                args=(tasks,),
                daemon=True,
                name="data-vault-migration",
            )
            with self._lock:
                self._thread = thread
            thread.start()
        else:
            self._run(tasks)
        return self.snapshot()

    def wait(self, timeout: float | None = None) -> dict:
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        return self.snapshot()

    def _run(self, tasks: list[_Task]) -> None:
        import src.state as state

        vault = get_data_vault(state._CONFIG_DIR)
        try:
            for task in tasks:
                with self._lock:
                    self._snapshot.current = task.label
                task.action()
                with self._lock:
                    self._snapshot.completed_files += 1
                    self._snapshot.completed_bytes += task.size
            # Save once more after every legacy file is protected, then persist
            # the completed version only after the entire migration succeeded.
            state._save_config()
            vault.mark_migration_complete(MIGRATION_VERSION)
            with self._lock:
                self._snapshot.state = "completed"
                self._snapshot.current = ""
                self._snapshot.error = ""
        except Exception as exc:
            with self._lock:
                self._snapshot.state = "failed"
                self._snapshot.current = ""
                self._snapshot.error = type(exc).__name__
        finally:
            with self._lock:
                self._thread = None

    @staticmethod
    def _size(path: Path) -> int:
        try:
            return int(path.stat().st_size)
        except OSError:
            return 0

    def _discover_tasks(self) -> list[_Task]:
        import src.state as state

        tasks: list[_Task] = []

        def add_file(label: str, path: Path, purpose: str) -> None:
            target = Path(path)
            if not target.is_file():
                return
            try:
                if target.read_bytes()[: len(FILE_MAGIC)] == FILE_MAGIC:
                    return
            except OSError:
                return
            tasks.append(_Task(
                label=label,
                path=target,
                size=self._size(target),
                action=lambda p=target, u=purpose: migrate_file_in_place(p, purpose=u),
            ))

        add_file("inbox_history", state.INBOX_HISTORY_PATH, "inbox-history")
        add_file("user_metadata", state.USER_METADATA_PATH, "user-metadata")
        add_file("guest_profiles", state.GUEST_PROFILES_PATH, "guest-profiles")
        add_file("session_groups", state._CONFIG_DIR / "session_groups.json", "session-groups")
        add_file("smart_collections", state._CONFIG_DIR / "smart_collections.json", "smart-collections")
        add_file("security_blocks", state._CONFIG_DIR / "security_blocks.json", "security-blocks")
        add_file("web_sessions", state.WEB_SESSIONS_PATH, "web-sessions-db")

        # unlock_codes keeps a long-lived SQLite connection; close it before
        # replacing the backing file with an encrypted serialized database.
        unlock_path = state._CONFIG_DIR / "unlock_codes.db"
        if unlock_path.is_file() and not self._already_encrypted(unlock_path):
            def migrate_unlock_codes(path=unlock_path):
                from src.core import unlock_codes
                unlock_codes.close_connection_for_vault_migration()
                return migrate_file_in_place(path, purpose="unlock-codes-db")
            tasks.append(_Task("unlock_codes", unlock_path, self._size(unlock_path), migrate_unlock_codes))

        add_file("cloud_token_key", state._CONFIG_DIR / "cloud_tokens.key", "cloud-token-key")

        thumb_root = state._CONFIG_DIR / "thumbnail_cache"
        for path in sorted(thumb_root.glob("*.jpg")) if thumb_root.exists() else ():
            add_file("thumbnail", path, f"thumbnail:{path.stem}")

        waveform_root = state._CONFIG_DIR / "waveforms"
        for path in sorted(waveform_root.glob("*.json")) if waveform_root.exists() else ():
            add_file("waveform", path, f"waveform:{path.stem}")

        for shared_root in tuple(state.SHARED_ROOTS):
            path = Path(shared_root.path) / ".netshare_index.cache"
            add_file("file_index", path, f"file-index:{shared_root.slot}")

        # Security event logs are append-only JSONL. Encrypt each record rather
        # than the whole file so rotation and future appends remain streaming.
        for path in sorted(state._CONFIG_DIR.glob("security_events.jsonl*")):
            if not path.is_file() or not self._security_log_needs_migration(path):
                continue
            tasks.append(_Task(
                "security_events",
                path,
                self._size(path),
                lambda p=path: self._migrate_security_jsonl(p),
            ))
        return tasks

    @staticmethod
    def _already_encrypted(path: Path) -> bool:
        try:
            with Path(path).open("rb") as handle:
                return handle.read(len(FILE_MAGIC)) == FILE_MAGIC
        except OSError:
            return False

    @staticmethod
    def _security_log_needs_migration(path: Path) -> bool:
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip() and not line.startswith("NSV1:"):
                    return True
        except OSError:
            pass
        return False

    @staticmethod
    def _migrate_security_jsonl(path: Path) -> bool:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        converted: list[str] = []
        changed = False
        for line in lines:
            text = line.strip()
            if not text:
                continue
            if text.startswith("NSV1:"):
                converted.append(text)
                continue
            try:
                value = json.loads(text)
            except (TypeError, ValueError):
                # Preserve unparseable legacy evidence verbatim rather than
                # silently deleting it during migration.
                converted.append(text)
                continue
            if isinstance(value, dict):
                converted.append(encode_jsonl_record(value, purpose="security-events"))
                changed = True
            else:
                converted.append(text)
        if not changed:
            return False
        temporary = path.with_name(f".{path.name}.vault-migrate.tmp")
        temporary.write_text("\n".join(converted) + ("\n" if converted else ""), encoding="utf-8")
        temporary.replace(path)
        return True


_CONTROLLER = DataVaultMigrationController()


def data_vault_migration_controller() -> DataVaultMigrationController:
    return _CONTROLLER


def migration_snapshot() -> dict:
    return _CONTROLLER.snapshot()


def start_migration_if_needed(*, force_sync: bool = False) -> dict:
    return _CONTROLLER.start_if_needed(force_sync=force_sync)
