"""
Common interface every cloud provider (Drive, Dropbox, Mega, ...) implements,
so the rest of the server (routes, premium locking, GUI) never needs to know
which provider it's talking to.

A provider is identified by (provider_id, account_id) -- a host can connect
more than one account of the same provider (e.g. two Drive accounts).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class StreamResult:
    """Result of a ranged/full download request against a cloud provider."""
    status: int                    # 200 (full) or 206 (partial content)
    headers: dict                  # Content-Type, Content-Length, Content-Range, Accept-Ranges
    chunks: object                 # iterator[bytes], or None on error
    error: str | None = None       # e.g. "quota_exceeded", "not_found", "auth_expired"


class CloudProviderError(Exception):
    """Raised for provider-level failures the caller should translate into
    an HTTP error for the mobile client (auth expired, quota, not found)."""
    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__(message or code)


class CloudProvider(ABC):
    """One connected cloud account. Instances are created by CloudManager
    from stored tokens/credentials -- never construct these directly from
    route handlers."""

    provider_id: str = "base"

    def __init__(self, account_id: str, token_data: dict):
        self.account_id = account_id
        self._token_data = token_data

    # Identity

    @property
    def account_label(self) -> str:
        return self._token_data.get("label") or self.account_id

    # Capability flags -- providers that can't truly proxy-stream (Mega, via
    # megatools) report False here so callers know a local temp copy will be
    # made instead of a true zero-copy proxy.
    supports_range_streaming: bool = True

    # Core operations

    @abstractmethod
    def list_files(self, folder_id: str = "root") -> list[dict]:
        """Return entries as {"id","name","is_dir","size","modified","mime_type"}."""
        raise NotImplementedError

    @abstractmethod
    def stream_file(self, file_id: str, range_header: str | None) -> StreamResult:
        """Return a StreamResult for a (possibly ranged) download."""
        raise NotImplementedError

    def refresh_if_needed(self) -> None:
        """Refresh OAuth tokens if close to expiry. No-op for providers that
        don't use OAuth (e.g. Mega/megatools)."""
        return None

    def to_token_data(self) -> dict:
        """Current token/credential blob to persist back to the TokenStore
        (e.g. after a refresh rotated the access token)."""
        return self._token_data
