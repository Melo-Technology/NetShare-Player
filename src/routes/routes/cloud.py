"""
Cloud provider bridge: /cloud/accounts, /cloud/list, /cloud/file, plus the
virtual-path helpers used to expose cloud folders inside /list and /file.
"""

from urllib.parse import quote, unquote

import src.state as state
from src.core import unlock_codes
from src.core.cloud import get_manager, CloudProviderError

_CLIENT_DISCONNECT_ERRORS = (
    BrokenPipeError,
    ConnectionResetError,
    ConnectionAbortedError,
)


class CloudRoutesMixin:

    _CLOUD_ERROR_STATUS = {
        "not_connected": 404,
        "missing_dependency": 503,
        "auth_expired": 401,
        "auth_failed": 401,
        "quota_exceeded": 503,
        "rate_limited": 429,
        "permission_denied": 403,
        "not_found": 404,
        "network_error": 502,
        "provider_unavailable": 503,
        "provider_error": 502,
        "unknown_provider": 400,
    }


    @staticmethod
    def _cloud_error_payload(error: CloudProviderError) -> dict:
        payload = {"error": error.code, "message": str(error)}
        details = getattr(error, "details", {})
        if isinstance(details, dict):
            if details.get("provider_code"):
                payload["provider_code"] = str(details["provider_code"])[:96]
            try:
                status = int(details.get("http_status") or 0)
            except (TypeError, ValueError):
                status = 0
            if status:
                payload["provider_http_status"] = status
        return payload

    def _send_cloud_error(self, provider_id: str, operation: str, error: CloudProviderError):
        payload = self._cloud_error_payload(error)
        status = self._CLOUD_ERROR_STATUS.get(error.code, 502)
        detail = payload.get("provider_code") or error.code
        http_status = payload.get("provider_http_status")
        suffix = f" upstream={http_status}" if http_status else ""
        state._emit(
            f"CLOUD {provider_id} {operation} failed: {error.code} ({detail}){suffix}",
            "error" if status >= 500 else "warn",
        )
        return self.send_json(payload, status)

    @staticmethod
    def _cloud_premium_path(provider_id: str, account_id: str, item_id: str) -> str:
        safe_item = quote(str(item_id or "root"), safe="")
        return f"/cloud/{provider_id}/{account_id}/{safe_item}"

    @staticmethod
    def _cloud_virtual_path(provider_id: str, account_id: str, item_id=None) -> str:
        base = f"/cloud/{quote(provider_id, safe='')}/{quote(account_id, safe='')}"
        return base if item_id is None else f"{base}/{quote(str(item_id), safe='')}"

    @staticmethod
    def _parse_cloud_virtual_path(path: str):
        parts = path.strip("/").split("/", 3)
        if len(parts) < 3 or parts[0] != "cloud":
            return None
        return (
            unquote(parts[1]),
            unquote(parts[2]),
            unquote(parts[3]) if len(parts) == 4 else "root",
        )

    def _decorate_cloud_entries(self, provider_id, account_id, entries, *, include_path=True):
        out = []
        device_id = self._device_id()
        for entry in entries:
            item = dict(entry)
            if include_path:
                item["path"] = self._cloud_virtual_path(
                    provider_id, account_id, item.get("id", "")
                )
                item["cloud_provider"] = provider_id
            premium_path = self._cloud_premium_path(
                provider_id, account_id, item.get("id", "")
            )
            item_lock = unlock_codes.lock_status_for_path(premium_path, device_id)
            if unlock_codes.get_premium_info(premium_path) is not None or item_lock["locked"]:
                item["premium"] = True
                item["locked"] = item_lock["locked"]
                item["premium_path"] = item_lock.get("folder_path")
                item["premium_label"] = item_lock.get("label", "")
                item["premium_price_note"] = item_lock.get("price_note", "")
            out.append(item)
        return out

    def _route_cloud_virtual_list(
        self, provider_id, account_id, folder_id, *, offset=None, limit=None, refresh=False,
    ):
        lock = self._lock_status(
            self._cloud_premium_path(provider_id, account_id, folder_id)
        )
        if lock["locked"]:
            return self._send_premium_locked(lock)
        try:
            if offset is not None or limit is not None:
                window = get_manager().list_files_window(
                    provider_id,
                    account_id,
                    folder_id,
                    offset=int(offset or 0),
                    limit=int(limit or 100),
                    force_refresh=bool(refresh),
                )
                payload = dict(window)
                payload["items"] = self._decorate_cloud_entries(
                    provider_id, account_id, window.get("items", []), include_path=True
                )
                return self.send_json(payload)
            entries = get_manager().list_files(
                provider_id, account_id, folder_id, force_refresh=bool(refresh)
            )
        except CloudProviderError as e:
            return self._send_cloud_error(provider_id, "list", e)
        self.send_json(
            self._decorate_cloud_entries(provider_id, account_id, entries, include_path=True)
        )

    def _route_cloud_accounts(self):
        """List connected cloud accounts (metadata only, never tokens)."""
        self.send_json(get_manager().connected_accounts())

    def _route_cloud_list(self, params):
        provider_id = params.get("provider", [""])[0]
        account_id = params.get("account", [""])[0]
        folder_id = params.get("folder", ["root"])[0]
        refresh = bool(params.get("refresh", [""])[0])
        paginated = "limit" in params or "offset" in params
        try:
            limit = min(max(int(params.get("limit", ["100"])[0]), 1), 200)
            offset = max(int(params.get("offset", ["0"])[0]), 0)
        except (ValueError, IndexError):
            return self.send_error_json("Invalid pagination", 400)
        if not provider_id or not account_id:
            return self.send_error_json("Missing 'provider' or 'account'", 400)
        folder_lock = self._lock_status(
            self._cloud_premium_path(provider_id, account_id, folder_id)
        )
        if folder_lock["locked"]:
            return self.send_json({
                "error": "premium_locked",
                "folder_path": folder_lock["folder_path"],
                "label": folder_lock["label"],
                "price_note": folder_lock["price_note"],
            }, 403)
        try:
            if paginated:
                window = get_manager().list_files_window(
                    provider_id, account_id, folder_id,
                    offset=offset, limit=limit, force_refresh=refresh,
                )
                payload = dict(window)
                payload["items"] = self._decorate_cloud_entries(
                    provider_id, account_id, window.get("items", []), include_path=False
                )
                return self.send_json(payload)
            entries = get_manager().list_files(
                provider_id, account_id, folder_id, force_refresh=refresh
            )
        except CloudProviderError as e:
            return self._send_cloud_error(provider_id, "list", e)
        self.send_json(
            self._decorate_cloud_entries(provider_id, account_id, entries, include_path=False)
        )

    def _route_cloud_file(self, params):
        provider_id = params.get("provider", [""])[0]
        account_id = params.get("account", [""])[0]
        file_id = params.get("id", [""])[0]
        if not provider_id or not account_id or not file_id:
            return self.send_error_json("Missing 'provider', 'account' or 'id'", 400)
        lock = self._lock_status(self._cloud_premium_path(provider_id, account_id, file_id))
        if lock["locked"]:
            return self.send_json({
                "error": "premium_locked",
                "folder_path": lock["folder_path"],
                "label": lock["label"],
                "price_note": lock["price_note"],
            }, 403)
        range_header = self.headers.get("Range")
        try:
            result = get_manager().stream_file(provider_id, account_id, file_id, range_header)
        except CloudProviderError as e:
            return self._send_cloud_error(provider_id, "file", e)
        if result.error or result.chunks is None:
            return self.send_json(
                {"error": result.error or "provider_error"},
                result.status if result.status >= 400 else 502,
            )
        try:
            self.send_response(result.status)
            for header, value in result.headers.items():
                self.send_header(header, value)
            self._send_cors_headers()
            self.end_headers()
            for chunk in result.chunks:
                self.wfile.write(chunk)
        except _CLIENT_DISCONNECT_ERRORS:
            pass  # client disconnected / seeked away mid-stream, not an error
