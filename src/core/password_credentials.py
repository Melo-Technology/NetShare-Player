"""Versioned password credentials shared by public-admin and web access."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import unicodedata
from dataclasses import dataclass

ALGORITHM = "pbkdf2_sha256"
VERSION = 1
ITERATIONS = 600_000
SALT_BYTES = 16
DERIVED_KEY_BYTES = 32
MIN_LENGTH = 12
MAX_LENGTH = 128


@dataclass(frozen=True)
class ParsedCredential:
    iterations: int
    salt: bytes
    digest: bytes


def generate_password() -> str:
    """Return a URL-safe password with about 144 bits of entropy."""
    return secrets.token_urlsafe(18)


def normalize_password(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    normalized = unicodedata.normalize("NFC", password)
    if normalized != normalized.strip():
        raise ValueError("password must not have leading or trailing whitespace")
    if not MIN_LENGTH <= len(normalized) <= MAX_LENGTH:
        raise ValueError(f"password must contain {MIN_LENGTH} to {MAX_LENGTH} characters")
    if not all(character.isprintable() for character in normalized):
        raise ValueError("password must contain printable characters only")
    return normalized


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    normalized = normalize_password(password)
    raw_salt = secrets.token_bytes(SALT_BYTES) if salt is None else bytes(salt)
    if len(raw_salt) != SALT_BYTES:
        raise ValueError("salt must contain exactly 16 bytes")
    digest = hashlib.pbkdf2_hmac(
        "sha256", normalized.encode("utf-8"), raw_salt, ITERATIONS, DERIVED_KEY_BYTES
    )
    salt_text = base64.urlsafe_b64encode(raw_salt).decode("ascii").rstrip("=")
    digest_text = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{ALGORITHM}$v={VERSION}$i={ITERATIONS}${salt_text}${digest_text}"


def _decode_urlsafe(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def parse_credential(value: str) -> ParsedCredential:
    try:
        algorithm, version, iterations, salt_text, digest_text = value.split("$")
        if algorithm != ALGORITHM or version != f"v={VERSION}":
            raise ValueError("unsupported password credential")
        count = int(iterations.removeprefix("i="))
        salt = _decode_urlsafe(salt_text)
        digest = _decode_urlsafe(digest_text)
    except (AttributeError, ValueError) as error:
        raise ValueError("invalid password credential") from error
    if count != ITERATIONS or len(salt) != SALT_BYTES or len(digest) != DERIVED_KEY_BYTES:
        raise ValueError("invalid password credential parameters")
    return ParsedCredential(count, salt, digest)


def verify_password(password: str, credential: str) -> bool:
    try:
        parsed = parse_credential(credential)
        normalized = unicodedata.normalize("NFC", str(password))
        actual = hashlib.pbkdf2_hmac(
            "sha256", normalized.encode("utf-8"), parsed.salt,
            parsed.iterations, DERIVED_KEY_BYTES,
        )
        return hmac.compare_digest(actual, parsed.digest)
    except (TypeError, ValueError):
        return False
