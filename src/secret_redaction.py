"""Best-effort redaction for secret-bearing diagnostic text.

This module is intentionally small and dependency-free so it can be used at
logging/Activity boundaries without creating a new failure path. It does not
attempt to classify arbitrary user text as a secret; instead it removes values
that are explicitly labelled with NetShare/authentication secret names or
standard Authorization headers.
"""
from __future__ import annotations

import re

_REDACTED = "<redacted>"

# Keep this list explicit: generic words such as ``key`` on their own would
# destroy useful diagnostics (message_key/public_key/etc.).
_SECRET_NAMES = (
    "password",
    "local_password",
    "admin_password",
    "community_password",
    "web_password",
    "client_secret",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "upload_token",
    "credential",
    "authorization",
    "auth",
    "totp",
    "totp_secret",
    "code",
    "private_key",
    "recovery_key",
    "recovery_phrase",
    "dek",
    "kek",
    "vault_key",
    "wrapped_dek",
    "remembered_key",
    "remember_material",
    "data_vault_key",
    "cloud_tokens.key",
)
_NAME = "|".join(sorted((re.escape(item) for item in _SECRET_NAMES), key=len, reverse=True))

# key=value / key: value / JSON-ish "key": "value". Values deliberately stop
# at common URL/log delimiters, while quoted values may contain spaces.
_QUOTED = re.compile(
    rf"(?P<prefix>(?:[\"']?(?:{_NAME})[\"']?)\s*[:=]\s*)(?P<quote>[\"'])(?P<value>.*?)(?P=quote)",
    re.IGNORECASE,
)
_UNQUOTED = re.compile(
    rf"(?P<prefix>(?:{_NAME})\s*[:=]\s*)(?![\"\'])(?P<value>[^\s&;,\]\}}]+)",
    re.IGNORECASE,
)
_AUTH_HEADER = re.compile(r"(?i)(authorization\s*:\s*)(?:bearer|basic)\s+[^\s,;]+")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+\-/]+=*")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)


def is_sensitive_secret_name(name: object) -> bool:
    """Return True for fields whose value must never cross diagnostics/API boundaries."""
    lowered = str(name or "").strip().lower()
    return bool(
        lowered in _SECRET_NAMES
        or any(part in lowered for part in ("password", "token", "secret", "credential", "private_key"))
    )


def redact_secret_text(value: object) -> str:
    """Return diagnostic text with labelled secret values removed.

    The function never raises for normal objects and intentionally leaves
    ciphertext, salts, non-secret fingerprints and field names visible.
    """
    try:
        text = str(value)
    except Exception:
        return "<unprintable>"
    try:
        text = _PRIVATE_KEY.sub("<redacted-private-key>", text)
        text = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}{_REDACTED}", text)
        text = _BEARER.sub(f"Bearer {_REDACTED}", text)
        text = _QUOTED.sub(lambda m: f"{m.group('prefix')}{m.group('quote')}{_REDACTED}{m.group('quote')}", text)
        text = _UNQUOTED.sub(lambda m: f"{m.group('prefix')}{_REDACTED}", text)
        return text
    except Exception:
        # Diagnostics must never become a crash vector.
        return text


__all__ = ["is_sensitive_secret_name", "redact_secret_text"]
