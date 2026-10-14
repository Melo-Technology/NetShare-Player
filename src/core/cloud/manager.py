"""
CloudManager -- the single entry point routes/handler.py talks to for all
cloud-provider operations.

Round 20.4 adds bounded provider pagination and a stale-while-revalidate cache:

* New mobile/Web clients can use the existing ``offset``/``limit`` HTTP
  contract without forcing Google Drive or Dropbox to enumerate a whole folder.
* Provider cursors never leave this module.  Offset checkpoints map NetShare
  offsets to provider cursors so sequential pagination is cheap.
* Fresh pages are returned from memory.  Stale pages are returned immediately
  while one background refresh updates the cache, avoiding UI stalls during
  transient provider latency.
* The legacy ``list_files`` contract is retained for older clients and uses the
  existing full-list cache.
"""

from __future__ import annotations

from collections import OrderedDict
import threading
import time

from src.core.cloud.base import CloudProvider, CloudProviderError, ListPage, StreamResult
from src.core.cloud.token_store import get_store

LIST_CACHE_TTL_SECONDS = 60
LIST_CACHE_STALE_SECONDS = 10 * 60
MAX_FULL_CACHE_ENTRIES = 128
MAX_PAGE_CACHE_ENTRIES = 512
MAX_PAGE_SIZE = 200


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
    def __init__(
        self,
        cache_ttl: float = LIST_CACHE_TTL_SECONDS,
        stale_ttl: float = LIST_CACHE_STALE_SECONDS,
    ):
        self._lock = threading.RLock()
        self._instances: dict[tuple, CloudProvider] = {}
        self._list_cache: OrderedDict[tuple, tuple[float, list]] = OrderedDict()
        self._page_cache: OrderedDict[tuple, tuple[float, ListPage]] = OrderedDict()
        self._offset_cursors: dict[tuple, dict[int, str | None]] = {}
        self._refreshing: set[tuple] = set()
        self._cache_ttl = max(0.0, float(cache_ttl))
        self._stale_ttl = max(self._cache_ttl, float(stale_ttl))

    # Account lifecycle

    def connected_accounts(self, provider_id: str | None = None) -> list[dict]:
        return get_store().list_accounts(provider_id)

    def register_account(self, provider_id: str, account_id: str, token_data: dict):
        get_store().set(provider_id, account_id, token_data)
        with self._lock:
            self._instances.pop((provider_id, account_id), None)
        self.invalidate_cache(provider_id, account_id)

    def disconnect(self, provider_id: str, account_id: str) -> bool:
        removed = get_store().delete(provider_id, account_id)
        with self._lock:
            self._instances.pop((provider_id, account_id), None)
        self.invalidate_cache(provider_id, account_id)
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

    @staticmethod
    def _copy_page(page: ListPage) -> ListPage:
        return ListPage(
            items=[dict(item) for item in page.items],
            next_cursor=page.next_cursor,
            has_more=bool(page.has_more),
        )

    def _put_full_cache(self, key: tuple, entries: list[dict]) -> None:
        with self._lock:
            self._list_cache[key] = (time.time(), [dict(item) for item in entries])
            self._list_cache.move_to_end(key)
            while len(self._list_cache) > MAX_FULL_CACHE_ENTRIES:
                self._list_cache.popitem(last=False)

    def _put_page_cache(self, key: tuple, page: ListPage) -> None:
        with self._lock:
            self._page_cache[key] = (time.time(), self._copy_page(page))
            self._page_cache.move_to_end(key)
            while len(self._page_cache) > MAX_PAGE_CACHE_ENTRIES:
                self._page_cache.popitem(last=False)

    # Listings (legacy full-list cache)

    def list_files(
        self, provider_id: str, account_id: str, folder_id: str = "root",
        force_refresh: bool = False,
    ) -> list[dict]:
        key = (provider_id, account_id, folder_id)
        cached = None
        if not force_refresh:
            with self._lock:
                cached = self._list_cache.get(key)
                if cached:
                    self._list_cache.move_to_end(key)
            if cached:
                age = time.time() - cached[0]
                if age < self._cache_ttl:
                    return [dict(item) for item in cached[1]]
                if age < self._stale_ttl:
                    self._schedule_full_refresh(key, provider_id, account_id, folder_id)
                    return [dict(item) for item in cached[1]]

        provider = self._get_instance(provider_id, account_id)
        try:
            entries = provider.list_files(folder_id)
        except CloudProviderError:
            if cached and (time.time() - cached[0]) < self._stale_ttl:
                return [dict(item) for item in cached[1]]
            raise
        self._persist_tokens(provider)
        self._put_full_cache(key, entries)
        return [dict(item) for item in entries]

    def _schedule_full_refresh(self, key, provider_id, account_id, folder_id) -> None:
        refresh_key = ("full",) + tuple(key)
        with self._lock:
            if refresh_key in self._refreshing:
                return
            self._refreshing.add(refresh_key)

        def run():
            try:
                provider = self._get_instance(provider_id, account_id)
                entries = provider.list_files(folder_id)
                self._persist_tokens(provider)
                self._put_full_cache(key, entries)
            except Exception:
                # Stale data remains valid until its bounded stale TTL expires.
                pass
            finally:
                with self._lock:
                    self._refreshing.discard(refresh_key)

        threading.Thread(target=run, name="CloudListRefresh", daemon=True).start()

    # Bounded pagination for mobile/Web

    def _fetch_page(
        self,
        provider_id: str,
        account_id: str,
        folder_id: str,
        cursor: str | None,
        limit: int,
    ) -> ListPage:
        provider = self._get_instance(provider_id, account_id)
        page = provider.list_files_page(folder_id, cursor=cursor, limit=limit)
        self._persist_tokens(provider)
        return page

    def _page_cache_key(
        self,
        provider_id: str,
        account_id: str,
        folder_id: str,
        cursor: str | None,
        limit: int,
    ) -> tuple:
        return (provider_id, account_id, folder_id, cursor or "", int(limit))

    def _get_page(
        self,
        provider_id: str,
        account_id: str,
        folder_id: str,
        cursor: str | None,
        limit: int,
        *,
        force_refresh: bool = False,
    ) -> tuple[ListPage, str]:
        limit = max(1, min(int(limit or 100), MAX_PAGE_SIZE))
        key = self._page_cache_key(provider_id, account_id, folder_id, cursor, limit)
        cached = None
        if not force_refresh:
            with self._lock:
                cached = self._page_cache.get(key)
                if cached:
                    self._page_cache.move_to_end(key)
            if cached:
                age = time.time() - cached[0]
                if age < self._cache_ttl:
                    return self._copy_page(cached[1]), "fresh"
                if age < self._stale_ttl:
                    self._schedule_page_refresh(key, provider_id, account_id, folder_id, cursor, limit)
                    return self._copy_page(cached[1]), "stale"

        try:
            page = self._fetch_page(provider_id, account_id, folder_id, cursor, limit)
        except CloudProviderError:
            if cached and (time.time() - cached[0]) < self._stale_ttl:
                return self._copy_page(cached[1]), "stale_if_error"
            raise
        self._put_page_cache(key, page)
        return self._copy_page(page), "miss"

    def _schedule_page_refresh(
        self, key, provider_id, account_id, folder_id, cursor, limit,
    ) -> None:
        refresh_key = ("page",) + tuple(key)
        with self._lock:
            if refresh_key in self._refreshing:
                return
            self._refreshing.add(refresh_key)

        def run():
            try:
                page = self._fetch_page(provider_id, account_id, folder_id, cursor, limit)
                self._put_page_cache(key, page)
            except Exception:
                pass
            finally:
                with self._lock:
                    self._refreshing.discard(refresh_key)

        threading.Thread(target=run, name="CloudPageRefresh", daemon=True).start()

    def list_files_window(
        self,
        provider_id: str,
        account_id: str,
        folder_id: str = "root",
        *,
        offset: int = 0,
        limit: int = 100,
        force_refresh: bool = False,
    ) -> dict:
        """Return one NetShare offset/limit window without enumerating a folder.

        Provider cursors are cached as checkpoints.  Sequential requests such as
        0..99, 100..199, ... therefore become one provider API request each.
        ``total`` is deliberately ``None`` because Drive/Dropbox cursor APIs do
        not provide an exact total without enumerating the entire directory.
        """
        offset = max(0, int(offset or 0))
        limit = max(1, min(int(limit or 100), MAX_PAGE_SIZE))
        base = (provider_id, account_id, folder_id)
        with self._lock:
            checkpoints = self._offset_cursors.setdefault(base, {0: None})
            starts = [value for value in checkpoints.keys() if value <= offset]
            start = max(starts) if starts else 0
            cursor = checkpoints.get(start)

        position = start
        output: list[dict] = []
        has_more = True
        cache_states: list[str] = []
        guard = 0

        while len(output) < limit and has_more:
            guard += 1
            if guard > 64:
                raise CloudProviderError("provider_error", "Cloud pagination exceeded the safety bound.")
            needed_skip = max(0, offset - position)
            request_size = min(MAX_PAGE_SIZE, max(limit - len(output) + needed_skip, 1))
            page, cache_state = self._get_page(
                provider_id,
                account_id,
                folder_id,
                cursor,
                request_size,
                force_refresh=force_refresh,
            )
            cache_states.append(cache_state)
            page_len = len(page.items)
            page_end = position + page_len

            if page.next_cursor:
                with self._lock:
                    self._offset_cursors.setdefault(base, {0: None})[page_end] = page.next_cursor

            if page_len == 0:
                has_more = bool(page.has_more and page.next_cursor)
                if not has_more:
                    break
                if page.next_cursor == cursor:
                    raise CloudProviderError("provider_error", "Cloud provider returned a repeated pagination cursor.")
                cursor = page.next_cursor
                position = page_end
                continue

            slice_start = max(0, offset - position)
            if slice_start < page_len:
                take = min(limit - len(output), page_len - slice_start)
                output.extend(dict(item) for item in page.items[slice_start:slice_start + take])

            has_more = bool(page.has_more)
            position = page_end
            if not page.has_more or not page.next_cursor:
                break
            if page.next_cursor == cursor:
                raise CloudProviderError("provider_error", "Cloud provider returned a repeated pagination cursor.")
            cursor = page.next_cursor

        next_offset = offset + len(output)
        if len(output) < limit and not has_more:
            has_more_result = False
        else:
            # If the current provider page still had unconsumed entries, there
            # is more even when its provider-level has_more flag is false.
            has_more_result = has_more or next_offset < position

        if not cache_states:
            cache_status = "miss"
        elif all(state == "fresh" for state in cache_states):
            cache_status = "fresh"
        elif any(state.startswith("stale") for state in cache_states):
            cache_status = "stale"
        else:
            cache_status = "miss"

        return {
            "items": output,
            "offset": offset,
            "limit": limit,
            "total": None,
            "total_known": False,
            "has_more": bool(has_more_result),
            "next_offset": next_offset if has_more_result else None,
            "cache_status": cache_status,
        }

    def invalidate_cache(self, provider_id: str | None = None, account_id: str | None = None):
        with self._lock:
            if provider_id is None:
                self._list_cache.clear()
                self._page_cache.clear()
                self._offset_cursors.clear()
                return
            self._list_cache = OrderedDict(
                (k, v) for k, v in self._list_cache.items()
                if not (k[0] == provider_id and (account_id is None or k[1] == account_id))
            )
            self._page_cache = OrderedDict(
                (k, v) for k, v in self._page_cache.items()
                if not (k[0] == provider_id and (account_id is None or k[1] == account_id))
            )
            self._offset_cursors = {
                k: v for k, v in self._offset_cursors.items()
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
