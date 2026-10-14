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


@dataclass
class ListPage:
    """One bounded page of a cloud directory listing.

    ``next_cursor`` is provider-internal and stays inside the server.  HTTP
    clients use NetShare's existing ``offset``/``limit`` contract instead of
    learning Google/Dropbox cursor formats.
    """
    items: list[dict] = field(default_factory=list)
    next_cursor: str | None = None
    has_more: bool = False


class CloudProviderError(Exception):
    """Provider failure carrying only data safe to surface to the host UI.

    ``details`` must never contain access/refresh tokens, OAuth authorization
    codes, PKCE verifiers or passwords.  Providers are responsible for
    sanitising upstream error responses before constructing this exception.
    """

    def __init__(self, code: str, message: str = "", *, details: dict | None = None):
        self.code = str(code or "provider_error")
        self.details = dict(details or {})
        super().__init__(str(message or self.code))


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

    def list_files_page(
        self, folder_id: str = "root", *, cursor: str | None = None, limit: int = 100,
    ) -> ListPage:
        """Return a bounded page.

        Providers with native cursor pagination should override this method.
        The fallback exists for bridges such as Mega and slices the legacy full
        listing so the HTTP contract remains uniform.
        """
        entries = self.list_files(folder_id)
        try:
            offset = max(0, int(cursor or 0))
        except (TypeError, ValueError):
            offset = 0
        page_size = max(1, min(int(limit or 100), 200))
        page = entries[offset:offset + page_size]
        next_offset = offset + len(page)
        has_more = next_offset < len(entries)
        return ListPage(
            items=page,
            next_cursor=str(next_offset) if has_more else None,
            has_more=has_more,
        )

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
