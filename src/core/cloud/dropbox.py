"""Dropbox read-only provider using installed-app OAuth 2.0 + PKCE.

NetShare is a distributed desktop application and therefore cannot safely embed a
Dropbox app secret.  The provider uses Dropbox's authorization-code PKCE flow,
requests offline access so refresh tokens are available, and verifies the token
against ``files/list_folder`` before persisting the account.

Only data safe for the desktop UI crosses the provider boundary.  OAuth codes,
PKCE verifiers, access/refresh tokens and Authorization values are never logged
or included in surfaced error messages.
"""

from __future__ import annotations

import re
import time
from typing import Iterator

from src.core.cloud.base import CloudProvider, CloudProviderError, ListPage, StreamResult
from src.core.cloud.oauth_utils import (
    generate_pkce_pair,
    generate_state,
    open_browser,
    start_callback_server,
    wait_for_callback,
)
from src.deps import HAS_REQUESTS

AUTH_ENDPOINT = "https://www.dropbox.com/oauth2/authorize"
TOKEN_ENDPOINT = "https://api.dropboxapi.com/oauth2/token"
API_BASE = "https://api.dropboxapi.com/2"
CONTENT_BASE = "https://content.dropboxapi.com/2"
# Dropbox requires redirect URIs to match an App Console entry exactly.  Unlike
# Google's installed-app loopback flow, an arbitrary ephemeral port is therefore
# not a reliable production contract.  Keep one stable loopback URI that the
# host can register once.
DROPBOX_CALLBACK_PORT = 53682
DROPBOX_REDIRECT_URI = f"http://127.0.0.1:{DROPBOX_CALLBACK_PORT}/"
_MAX_PROVIDER_MESSAGE = 300

_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(access_token|refresh_token|id_token|code_verifier|client_secret|authorization_code|code)"
    r"\s*[:=]\s*([^\s,&]+)"
)
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def _safe_provider_message(value: object, fallback: str) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return fallback
    text = _SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = _BEARER_VALUE.sub("Bearer <redacted>", text)
    return text[:_MAX_PROVIDER_MESSAGE]


def _response_error(response, *, fallback_code: str, fallback_message: str) -> CloudProviderError:
    provider_code = ""
    provider_message = ""
    try:
        payload = response.json()
    except Exception:
        payload = None
    if isinstance(payload, dict):
        raw_error = payload.get("error")
        if isinstance(raw_error, str):
            provider_code = raw_error
        elif isinstance(raw_error, dict):
            provider_code = str(raw_error.get(".tag") or raw_error.get("tag") or "")
        provider_message = str(
            payload.get("error_description")
            or payload.get("error_summary")
            or payload.get("user_message")
            or ""
        )
    details = {"http_status": int(getattr(response, "status_code", 0) or 0)}
    if provider_code:
        details["provider_code"] = _safe_provider_message(provider_code, "provider_error")[:96]
    retry_after = str(getattr(response, "headers", {}).get("Retry-After", "") or "").strip()
    if retry_after.isdigit():
        details["retry_after"] = min(int(retry_after), 86400)
    return CloudProviderError(
        fallback_code,
        _safe_provider_message(provider_message, fallback_message),
        details=details,
    )


def _require_access_token(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise CloudProviderError("token_response_invalid", "Dropbox returned an invalid token response.")
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise CloudProviderError("token_response_invalid", "Dropbox returned an invalid token response.")
    return payload


def connect(app_key: str, label: str = "", timeout: int = 180) -> dict:
    """Run Dropbox's bounded Desktop-app PKCE flow and verify file access."""
    clean_app_key = str(app_key or "").strip()
    if not clean_app_key:
        raise CloudProviderError("app_key_required", "Dropbox app key is required.")
    if not HAS_REQUESTS:
        raise CloudProviderError(
            "missing_dependency",
            "Dropbox requires the 'requests' package (pip install requests).",
        )
    import requests

    verifier, challenge = generate_pkce_pair()
    oauth_state = generate_state()
    try:
        server, port = start_callback_server(
            DROPBOX_CALLBACK_PORT, expected_state=oauth_state
        )
    except OSError as error:
        raise CloudProviderError(
            "callback_port_unavailable",
            f"Dropbox callback port {DROPBOX_CALLBACK_PORT} is unavailable. Close the other app using it and retry.",
            details={"callback_port": DROPBOX_CALLBACK_PORT},
        ) from error
    redirect_uri = DROPBOX_REDIRECT_URI

    params = {
        "client_id": clean_app_key,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "token_access_type": "offline",
        "state": oauth_state,
    }
    auth_url = AUTH_ENDPOINT + "?" + requests.compat.urlencode(params)
    if open_browser(auth_url) is False:
        server.server_close()
        raise CloudProviderError("browser_open_failed", "Could not open the browser for Dropbox authorization.")

    result = wait_for_callback(server, timeout=timeout, expected_state=oauth_state)
    if not result:
        raise CloudProviderError("timeout", "No valid response from the browser consent screen before timeout.")
    if result.get("state", [""])[0] != oauth_state:
        raise CloudProviderError("state_mismatch", "OAuth state mismatch; the callback was rejected.")
    if "error" in result:
        provider_code = str(result.get("error", ["oauth_denied"])[0] or "oauth_denied")
        description = str(result.get("error_description", [""])[0] or "")
        raise CloudProviderError(
            "oauth_denied",
            _safe_provider_message(description, "Dropbox authorization was denied."),
            details={"provider_code": _safe_provider_message(provider_code, "oauth_denied")[:96]},
        )
    code = str(result.get("code", [""])[0] or "")
    if not code:
        raise CloudProviderError("no_code", "Authorization code missing from callback.")

    try:
        resp = requests.post(
            TOKEN_ENDPOINT,
            data={
                # Dropbox's supported public-client PKCE flow uses the app key
                # together with the verifier; no app secret is embedded.
                "client_id": clean_app_key,
                "code": code,
                "code_verifier": verifier,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            timeout=30,
        )
    except requests.RequestException as error:
        raise CloudProviderError(
            "network_error",
            "Could not reach Dropbox's token endpoint.",
            details={"provider_code": type(error).__name__},
        ) from error
    if resp.status_code != 200:
        raise _response_error(
            resp,
            fallback_code="token_exchange_failed",
            fallback_message=f"Dropbox rejected the token exchange (HTTP {resp.status_code}).",
        )
    try:
        payload = _require_access_token(resp.json())
    except ValueError as error:
        raise CloudProviderError("token_response_invalid", "Dropbox returned invalid JSON from the token endpoint.") from error

    # Verify the exact read capability NetShare needs before registering the
    # account.  This catches missing files.metadata.read permission and invalid
    # app configuration immediately without requiring the broader account-info
    # scope merely to obtain a display name.
    try:
        verify = requests.post(
            f"{API_BASE}/files/list_folder",
            headers={
                "Authorization": f"Bearer {payload['access_token']}",
                "Content-Type": "application/json",
            },
            json={"path": "", "limit": 1},
            timeout=20,
        )
    except requests.RequestException as error:
        raise CloudProviderError(
            "network_error",
            "Authorization succeeded, but NetShare could not verify Dropbox file access.",
            details={"provider_code": type(error).__name__},
        ) from error
    if verify.status_code != 200:
        raise _response_error(
            verify,
            fallback_code="dropbox_verification_failed",
            fallback_message=f"Dropbox file access verification failed (HTTP {verify.status_code}).",
        )

    try:
        expires_in = float(payload.get("expires_in") or 14400)
    except (TypeError, ValueError):
        expires_in = 14400.0
    account_id = str(payload.get("account_id") or "").strip()
    account_label = str(label or account_id or "Dropbox").strip() or "Dropbox"

    return {
        "app_key": clean_app_key,
        "access_token": payload["access_token"],
        "refresh_token": str(payload.get("refresh_token") or ""),
        "expires_at": time.time() + max(1.0, expires_in),
        "label": account_label,
        "account_id": account_id,
    }


class DropboxProvider(CloudProvider):
    provider_id = "dropbox"
    supports_range_streaming = True

    def refresh_if_needed(self) -> None:
        if not HAS_REQUESTS:
            raise CloudProviderError("missing_dependency", "requests not installed")
        if time.time() < float(self._token_data.get("expires_at", 0) or 0) - 60:
            return
        refresh_token = self._token_data.get("refresh_token")
        if not refresh_token:
            raise CloudProviderError("auth_expired", "No refresh token stored; reconnect this account.")
        app_key = str(self._token_data.get("app_key") or "").strip()
        if not app_key:
            raise CloudProviderError("auth_expired", "Dropbox app key is missing; reconnect this account.")
        import requests
        try:
            resp = requests.post(
                TOKEN_ENDPOINT,
                data={
                    "client_id": app_key,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
                timeout=30,
            )
        except requests.RequestException as error:
            raise CloudProviderError("network_error", "Could not refresh the Dropbox session.") from error
        if resp.status_code != 200:
            raise _response_error(
                resp,
                fallback_code="auth_expired",
                fallback_message="Dropbox token refresh failed; reconnect this account.",
            )
        try:
            payload = _require_access_token(resp.json())
        except ValueError as error:
            raise CloudProviderError("auth_expired", "Dropbox returned an invalid refresh response.") from error
        try:
            expires_in = float(payload.get("expires_in") or 14400)
        except (TypeError, ValueError):
            expires_in = 14400.0
        self._token_data["access_token"] = payload["access_token"]
        self._token_data["expires_at"] = time.time() + max(1.0, expires_in)
        # Dropbox normally keeps the existing refresh token, but accept a
        # rotated value if the provider returns one in the future.
        if isinstance(payload.get("refresh_token"), str) and payload["refresh_token"]:
            self._token_data["refresh_token"] = payload["refresh_token"]

    def _headers(self) -> dict:
        self.refresh_if_needed()
        token = str(self._token_data.get("access_token") or "")
        if not token:
            raise CloudProviderError("auth_expired", "Dropbox access token is missing; reconnect this account.")
        return {"Authorization": f"Bearer {token}"}

    def _list_response_error(self, resp):
        if resp.status_code == 401:
            return CloudProviderError("auth_expired", "Dropbox session expired; reconnect this account.")
        if resp.status_code == 403:
            return _response_error(resp, fallback_code="permission_denied", fallback_message="Dropbox denied access to this folder.")
        if resp.status_code == 429:
            return _response_error(resp, fallback_code="rate_limited", fallback_message="Dropbox API rate limit reached.")
        if resp.status_code in {500, 502, 503, 504}:
            return _response_error(resp, fallback_code="provider_unavailable", fallback_message="Dropbox is temporarily unavailable.")
        if resp.status_code == 409:
            return _response_error(resp, fallback_code="not_found", fallback_message="Dropbox folder was not found or is no longer accessible.")
        return _response_error(resp, fallback_code="provider_error", fallback_message=f"Dropbox returned HTTP {resp.status_code}.")

    def list_files_page(
        self, folder_id: str = "", *, cursor: str | None = None, limit: int = 100,
    ) -> ListPage:
        import requests

        page_size = max(1, min(int(limit or 100), 200))
        headers = {**self._headers(), "Content-Type": "application/json"}
        if cursor:
            endpoint = f"{API_BASE}/files/list_folder/continue"
            request_payload = {"cursor": str(cursor)}
        else:
            endpoint = f"{API_BASE}/files/list_folder"
            path = "" if folder_id in ("root", "") else str(folder_id)
            request_payload = {"path": path, "limit": page_size}

        resp = None
        last_error = None
        for attempt, delay in enumerate((0.0, 0.25, 0.75)):
            if delay:
                time.sleep(delay)
            try:
                resp = requests.post(endpoint, headers=headers, json=request_payload, timeout=20)
            except requests.RequestException as error:
                last_error = error
                if attempt < 2:
                    continue
                raise CloudProviderError(
                    "network_error",
                    "Could not reach Dropbox.",
                    details={"provider_code": type(error).__name__},
                ) from error
            if resp.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                continue
            break

        if resp is None:
            raise CloudProviderError(
                "network_error",
                "Could not reach Dropbox.",
                details={"provider_code": type(last_error).__name__ if last_error else "request_failed"},
            )
        if resp.status_code != 200:
            raise self._list_response_error(resp)
        try:
            payload = resp.json()
        except ValueError as error:
            raise CloudProviderError("provider_error", "Dropbox returned invalid JSON.") from error
        entries = payload.get("entries") if isinstance(payload, dict) else None
        if not isinstance(entries, list):
            raise CloudProviderError("provider_error", "Dropbox returned an invalid folder listing.")

        out: list[dict] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            path_lower = str(entry.get("path_lower") or "").strip()
            if not name or not path_lower:
                continue
            is_dir = entry.get(".tag") == "folder"
            size = entry.get("size")
            out.append({
                "id": path_lower,
                "name": name,
                "is_dir": is_dir,
                "size": None if is_dir else (int(size) if isinstance(size, int) and size >= 0 else None),
                "modified": str(entry.get("server_modified") or ""),
                "mime_type": "",
            })

        has_more = bool(payload.get("has_more"))
        next_cursor = str(payload.get("cursor") or "") if has_more else ""
        if has_more and not next_cursor:
            raise CloudProviderError("provider_error", "Dropbox returned a missing pagination cursor.")
        return ListPage(items=out, next_cursor=next_cursor or None, has_more=has_more)

    def list_files(self, folder_id: str = "") -> list[dict]:
        """Legacy full-directory contract, consuming bounded cursor pages."""
        out: list[dict] = []
        cursor = None
        seen: set[str] = set()
        while True:
            page = self.list_files_page(folder_id, cursor=cursor, limit=200)
            out.extend(page.items)
            if not page.has_more or not page.next_cursor:
                return out
            if page.next_cursor in seen:
                raise CloudProviderError("provider_error", "Dropbox returned an invalid or repeated pagination cursor.")
            seen.add(page.next_cursor)
            cursor = page.next_cursor

    def stream_file(self, file_id: str, range_header: str | None) -> StreamResult:
        import json as _json
        import requests
        headers = {**self._headers(), "Dropbox-API-Arg": _json.dumps({"path": file_id})}
        if range_header:
            headers["Range"] = range_header
        try:
            resp = requests.post(
                f"{CONTENT_BASE}/files/download",
                headers=headers,
                stream=True,
                timeout=30,
            )
        except requests.RequestException:
            return StreamResult(status=502, headers={}, chunks=None, error="network_error")

        if resp.status_code == 401:
            resp.close()
            return StreamResult(status=401, headers={}, chunks=None, error="auth_expired")
        if resp.status_code == 403:
            resp.close()
            return StreamResult(status=403, headers={}, chunks=None, error="permission_denied")
        if resp.status_code == 429:
            resp.close()
            return StreamResult(status=429, headers={}, chunks=None, error="rate_limited")
        if resp.status_code == 409:
            resp.close()
            return StreamResult(status=404, headers={}, chunks=None, error="not_found")
        if resp.status_code in {500, 502, 503, 504}:
            resp.close()
            return StreamResult(status=503, headers={}, chunks=None, error="provider_unavailable")
        if resp.status_code not in (200, 206):
            resp.close()
            return StreamResult(status=502, headers={}, chunks=None, error="provider_error")

        out_headers = {"Accept-Ranges": "bytes"}
        for header_name in ("Content-Type", "Content-Length", "Content-Range"):
            if header_name in resp.headers:
                out_headers[header_name] = resp.headers[header_name]

        def _iter() -> Iterator[bytes]:
            try:
                for chunk in resp.iter_content(chunk_size=256 * 1024):
                    if chunk:
                        yield chunk
            finally:
                resp.close()

        return StreamResult(status=resp.status_code, headers=out_headers, chunks=_iter())
