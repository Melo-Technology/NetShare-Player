"""
CloudManager -- the single entry point routes/handler.py talks to for all
cloud-provider operations. Responsibilities:

  - Instantiate/cache the right CloudProvider object for a (provider_id,
    account_id) pair, backed by TokenStore.
  - Cache directory listings for a short TTL, since every folder open on
    the mobile client would otherwise be a live API call (rate-limit risk,
    validated tradeoff from the clarification round).
  - Persist tokens back to disk whenever a provider rotates them (OAuth
    refresh), so the host never has to reconnect after every access-token
    expiry.
  - Normalize provider errors (quota, auth expired, not found) into a
    consistent shape the HTTP layer can turn into clean status codes.
"""

import threading
import time

from src.core.cloud.base import CloudProvider, CloudProviderError, StreamResult
from src.core.cloud.token_store import get_store

LIST_CACHE_TTL_SECONDS = 60


def _provider_class(provider_id: str):
    if provider_id == "drive":
        from src.core.cloud.drive import GoogleDriveProvider
        return GoogleDriveProvider
    if provider_id == "dropbox":
        from src.core.cloud.dropbox import DropboxProvider
        return DropboxProvider
    if provider_id == "mega":
        from src.core.cloud.mega import MegaProvider
        return MegaProvider
    raise CloudProviderError("unknown_provider", provider_id)


class CloudManager:
    def __init__(self, cache_ttl: float = LIST_CACHE_TTL_SECONDS):
        self._lock = threading.RLock()
        self._instances: dict[tuple, CloudProvider] = {}
        self._list_cache: dict[tuple, tuple[float, list]] = {}
        self._cache_ttl = cache_ttl

    # Account lifecycle

    def connected_accounts(self, provider_id: str | None = None) -> list[dict]:
        return get_store().list_accounts(provider_id)

    def register_account(self, provider_id: str, account_id: str, token_data: dict):
        get_store().set(provider_id, account_id, token_data)
        with self._lock:
            self._instances.pop((provider_id, account_id), None)

    def disconnect(self, provider_id: str, account_id: str) -> bool:
        removed = get_store().delete(provider_id, account_id)
        with self._lock:
            self._instances.pop((provider_id, account_id), None)
            stale = [k for k in self._list_cache if k[0] == provider_id and k[1] == account_id]
            for k in stale:
                self._list_cache.pop(k, None)
        return removed

    def _get_instance(self, provider_id: str, account_id: str) -> CloudProvider:
        key = (provider_id, account_id)
        with self._lock:
            if key in self._instances:
                return self._instances[key]
        token_data = get_store().get(provider_id, account_id)
        if token_data is None:
            raise CloudProviderError("not_connected", f"{provider_id}/{account_id} is not connected")
        instance = _provider_class(provider_id)(account_id, token_data)
        with self._lock:
            self._instances[key] = instance
        return instance

    def _persist_tokens(self, provider: CloudProvider):
        get_store().set(provider.provider_id, provider.account_id, provider.to_token_data())

    # Listings (cached)

    def list_files(
        self, provider_id: str, account_id: str, folder_id: str = "root",
        force_refresh: bool = False,
    ) -> list[dict]:
        key = (provider_id, account_id, folder_id)
        if not force_refresh:
            with self._lock:
                cached = self._list_cache.get(key)
            if cached and (time.time() - cached[0]) < self._cache_ttl:
                return cached[1]
        provider = self._get_instance(provider_id, account_id)
        entries = provider.list_files(folder_id)
        self._persist_tokens(provider)
        with self._lock:
            self._list_cache[key] = (time.time(), entries)
        return entries

    def invalidate_cache(self, provider_id: str | None = None, account_id: str | None = None):
        with self._lock:
            if provider_id is None:
                self._list_cache.clear()
                return
            self._list_cache = {
                k: v for k, v in self._list_cache.items()
                if not (k[0] == provider_id and (account_id is None or k[1] == account_id))
            }

    # Streaming (never cached)

    def stream_file(
        self, provider_id: str, account_id: str, file_id: str, range_header: str | None,
    ) -> StreamResult:
        provider = self._get_instance(provider_id, account_id)
        result = provider.stream_file(file_id, range_header)
        self._persist_tokens(provider)
        return result

    def supports_range_streaming(self, provider_id: str, account_id: str) -> bool:
        return self._get_instance(provider_id, account_id).supports_range_streaming


_manager: CloudManager | None = None
_manager_lock = threading.Lock()


def get_manager() -> CloudManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = CloudManager()
        return _manager
