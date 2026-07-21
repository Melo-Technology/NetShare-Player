"""
Dropbox provider. Same PKCE "installed app" pattern as Drive -- see
drive.py's module docstring for the reasoning around the `requests`
dependency and why the host must supply their own App key (Dropbox App
Console > Create app > Scoped access > "files.content.read" scope only).
"""

import time
from typing import Iterator

from src.core.cloud.base import CloudProvider, CloudProviderError, StreamResult
from src.core.cloud.oauth_utils import (
    generate_pkce_pair, generate_state, start_callback_server,
    wait_for_callback, open_browser,
)
from src.deps import HAS_REQUESTS

AUTH_ENDPOINT = "https://www.dropbox.com/oauth2/authorize"
TOKEN_ENDPOINT = "https://api.dropboxapi.com/oauth2/token"
API_BASE = "https://api.dropboxapi.com/2"
CONTENT_BASE = "https://content.dropboxapi.com/2"


def connect(app_key: str, label: str = "", timeout: int = 180) -> dict:
    if not HAS_REQUESTS:
        raise CloudProviderError(
            "missing_dependency",
            "Dropbox requires the 'requests' package (pip install requests).",
        )
    import requests

    verifier, challenge = generate_pkce_pair()
    oauth_state = generate_state()
    server, port = start_callback_server()
    redirect_uri = f"http://127.0.0.1:{port}/"

    params = {
        "client_id": app_key,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "token_access_type": "offline",
        "state": oauth_state,
    }
    auth_url = AUTH_ENDPOINT + "?" + requests.compat.urlencode(params)
    open_browser(auth_url)

    result = wait_for_callback(server, timeout=timeout)
    if not result:
        raise CloudProviderError("timeout", "No response from the browser consent screen.")
    if result.get("state", [""])[0] != oauth_state:
        raise CloudProviderError("state_mismatch", "OAuth state mismatch -- possible CSRF, aborted.")
    if "error" in result:
        raise CloudProviderError("oauth_denied", result["error"][0])
    code = result.get("code", [""])[0]
    if not code:
        raise CloudProviderError("no_code", "Authorization code missing from callback.")

    resp = requests.post(TOKEN_ENDPOINT, data={
        "client_id": app_key,
        "code": code,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }, timeout=30)
    if resp.status_code != 200:
        raise CloudProviderError("token_exchange_failed", resp.text[:300])
    payload = resp.json()

    account_label = label or payload.get("account_id", "Dropbox")

    return {
        "app_key": app_key,
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token", ""),
        "expires_at": time.time() + payload.get("expires_in", 14400),
        "label": account_label,
    }


class DropboxProvider(CloudProvider):
    provider_id = "dropbox"
    supports_range_streaming = True

    def refresh_if_needed(self) -> None:
        if not HAS_REQUESTS:
            raise CloudProviderError("missing_dependency", "requests not installed")
        if time.time() < self._token_data.get("expires_at", 0) - 60:
            return
        refresh_token = self._token_data.get("refresh_token")
        if not refresh_token:
            raise CloudProviderError("auth_expired", "No refresh token stored; reconnect this account.")
        import requests
        resp = requests.post(TOKEN_ENDPOINT, data={
            "client_id": self._token_data["app_key"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }, timeout=30)
        if resp.status_code != 200:
            raise CloudProviderError("auth_expired", "Token refresh failed; reconnect this account.")
        payload = resp.json()
        self._token_data["access_token"] = payload["access_token"]
        self._token_data["expires_at"] = time.time() + payload.get("expires_in", 14400)

    def _headers(self) -> dict:
        self.refresh_if_needed()
        return {"Authorization": f"Bearer {self._token_data['access_token']}"}

    def list_files(self, folder_id: str = "") -> list[dict]:
        """folder_id here is a Dropbox path ("" = root, "/Photos" = subfolder)."""
        import requests
        path = "" if folder_id in ("root", "") else folder_id
        resp = requests.post(
            f"{API_BASE}/files/list_folder",
            headers={**self._headers(), "Content-Type": "application/json"},
            json={"path": path},
            timeout=30,
        )
        if resp.status_code == 401:
            raise CloudProviderError("auth_expired", "Dropbox session expired; reconnect this account.")
        if resp.status_code == 429:
            raise CloudProviderError("quota_exceeded", "Dropbox API rate limit hit.")
        if resp.status_code != 200:
            raise CloudProviderError("provider_error", resp.text[:300])
        out = []
        for entry in resp.json().get("entries", []):
            is_dir = entry.get(".tag") == "folder"
            out.append({
                "id": entry["path_lower"],
                "name": entry["name"],
                "is_dir": is_dir,
                "size": None if is_dir else entry.get("size"),
                "modified": entry.get("server_modified", ""),
                "mime_type": "" if is_dir else "",
            })
        return out

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
        except requests.RequestException as e:
            return StreamResult(status=502, headers={}, chunks=None, error=str(e))

        if resp.status_code == 401:
            return StreamResult(status=401, headers={}, chunks=None, error="auth_expired")
        if resp.status_code == 429:
            return StreamResult(status=503, headers={}, chunks=None, error="quota_exceeded")
        if resp.status_code == 409:
            return StreamResult(status=404, headers={}, chunks=None, error="not_found")
        if resp.status_code not in (200, 206):
            return StreamResult(status=502, headers={}, chunks=None, error="provider_error")

        out_headers = {"Accept-Ranges": "bytes"}
        for h in ("Content-Type", "Content-Length", "Content-Range"):
            if h in resp.headers:
                out_headers[h] = resp.headers[h]

        def _iter() -> Iterator[bytes]:
            try:
                for chunk in resp.iter_content(chunk_size=256 * 1024):
                    if chunk:
                        yield chunk
            finally:
                resp.close()

        return StreamResult(status=resp.status_code, headers=out_headers, chunks=_iter())
