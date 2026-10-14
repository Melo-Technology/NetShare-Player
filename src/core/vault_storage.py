"""Vault-aware persistence helpers for sensitive NetShare internal data."""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Any

from src.core.data_vault import FILE_MAGIC, VaultLockedError, get_data_vault


def _vault():
    import src.state as state
    return get_data_vault(state._CONFIG_DIR)


def is_encrypted_payload(payload: bytes) -> bool:
    return bytes(payload).startswith(FILE_MAGIC)


def _atomic_write(path: Path, payload: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def read_bytes(path: Path, *, purpose: str, default: bytes | None = None) -> bytes:
    target = Path(path)
    try:
        payload = target.read_bytes()
    except OSError:
        if default is not None:
            return bytes(default)
        raise
    vault = _vault()
    if is_encrypted_payload(payload):
        return vault.decrypt_bytes(payload, purpose=purpose)
    if vault.configured:
        if not vault.unlocked:
            raise VaultLockedError("vault_locked")
        # Legacy plaintext remains readable only during the migration window.
        return payload
    return payload


def write_bytes(path: Path, payload: bytes, *, purpose: str) -> None:
    target = Path(path)
    vault = _vault()
    if vault.configured:
        _atomic_write(target, vault.encrypt_bytes(bytes(payload), purpose=purpose))
    else:
        _atomic_write(target, bytes(payload))


def read_json(path: Path, *, purpose: str, default: Any) -> Any:
    try:
        raw = read_bytes(path, purpose=purpose)
        return json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, TypeError, UnicodeError):
        return default


def write_json(path: Path, value: Any, *, purpose: str, indent: int | None = None) -> None:
    payload = json.dumps(value, ensure_ascii=False, separators=None if indent else (",", ":"), indent=indent).encode("utf-8")
    write_bytes(path, payload, purpose=purpose)


def read_jsonl(path: Path, *, purpose: str, limit: int | None = None) -> list[dict]:
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError:
        return []
    vault = _vault()
    rows: list[dict] = []
    if is_encrypted_payload(raw):
        try:
            text = vault.decrypt_bytes(raw, purpose=purpose).decode("utf-8", errors="replace")
        except Exception:
            return []
        lines = text.splitlines()
    else:
        if vault.configured and not vault.unlocked:
            raise VaultLockedError("vault_locked")
        lines = raw.decode("utf-8", errors="replace").splitlines()
    if limit is not None:
        lines = lines[-max(0, int(limit)):]
    for line in lines:
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
        except (ValueError, TypeError):
            continue
    return rows


def write_jsonl(path: Path, rows: list[dict], *, purpose: str) -> None:
    payload = "\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows)
    if payload:
        payload += "\n"
    write_bytes(path, payload.encode("utf-8"), purpose=purpose)


def migrate_file_in_place(path: Path, *, purpose: str) -> bool:
    """Encrypt one legacy plaintext file atomically if a vault is active."""
    target = Path(path)
    if not target.exists() or not target.is_file():
        return False
    raw = target.read_bytes()
    if not raw or is_encrypted_payload(raw):
        return False
    vault = _vault()
    if not vault.configured:
        return False
    if not vault.unlocked:
        raise VaultLockedError("vault_locked")
    _atomic_write(target, vault.encrypt_bytes(raw, purpose=purpose))
    return True


def encode_jsonl_record(value: dict, *, purpose: str) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    vault = _vault()
    if not vault.configured:
        return raw.decode("utf-8")
    encrypted = vault.encrypt_bytes(raw, purpose=f"{purpose}:record")
    return "NSV1:" + base64.urlsafe_b64encode(encrypted).decode("ascii")


def decode_jsonl_record(line: str, *, purpose: str) -> dict | None:
    text = str(line or "").strip()
    if not text:
        return None
    vault = _vault()
    try:
        if text.startswith("NSV1:"):
            payload = base64.urlsafe_b64decode(text[5:].encode("ascii"))
            raw = vault.decrypt_bytes(payload, purpose=f"{purpose}:record")
            value = json.loads(raw.decode("utf-8"))
        else:
            if vault.configured and not vault.unlocked:
                raise VaultLockedError("vault_locked")
            value = json.loads(text)
        return value if isinstance(value, dict) else None
    except VaultLockedError:
        raise
    except Exception:
        return None
