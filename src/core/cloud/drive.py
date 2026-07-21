"""
Google Drive provider.

Scope requested is drive.readonly -- NetShare never needs write access to
the host's Drive.
"""

import time
from typing import Iterator

from src.core.cloud.base import CloudProvider, CloudProviderError, StreamResult
from src.core.cloud.oauth_utils import (
    generate_pkce_pair, generate_state, start_callback_server,
    wait_for_callback, open_browser,
)
from src.deps import HAS_REQUESTS

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
API_BASE = "https://www.googleapis.com/drive/v3"
SCOPE = "https://www.googleapis.com/auth/drive.readonly"

FOLDER_MIME = "application/vnd.google-apps.folder"


def connect(client_id: str, label: str = "", timeout: int = 180) -> dict:
    """
    Run the interactive PKCE "installed app" OAuth flow. Blocks until the
    host finishes the browser consent screen or times out -- call from a
    background thread, never the Tk main thread.

    Returns a token_data dict ready for TokenStore.set(), or raises
    CloudProviderError with a code the GUI can turn into a clear message.
    """
    if not HAS_REQUESTS:
        raise CloudProviderError(
            "missing_dependency",
            "Google Drive requires the 'requests' package (pip install requests).",
        )
    import requests

    verifier, challenge = generate_pkce_pair()
    oauth_state = generate_state()
    server, port = start_callback_server()
    redirect_uri = f"http://127.0.0.1:{port}/"

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
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
        "client_id": client_id,
        "code": code,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }, timeout=30)
    if resp.status_code != 200:
        raise CloudProviderError("token_exchange_failed", resp.text[:300])
    payload = resp.json()

    account_label = label
    if not account_label:
        try:
            who = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {payload['access_token']}"},
                timeout=15,
            )
            if who.status_code == 200:
                account_label = who.json().get("email", "Google Drive")
        except Exception:
            account_label = "Google Drive"

    return {
        "client_id": client_id,
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token", ""),
        "expires_at": time.time() + payload.get("expires_in", 3600),
        "label": account_label or "Google Drive",
    }


class GoogleDriveProvider(CloudProvider):
    provider_id = "drive"
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
            "client_id": self._token_data["client_id"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }, timeout=30)
        if resp.status_code != 200:
            raise CloudProviderError("auth_expired", "Token refresh failed; reconnect this account.")
        payload = resp.json()
        self._token_data["access_token"] = payload["access_token"]
        self._token_data["expires_at"] = time.time() + payload.get("expires_in", 3600)

    def _headers(self) -> dict:
        self.refresh_if_needed()
        return {"Authorization": f"Bearer {self._token_data['access_token']}"}

    def list_files(self, folder_id: str = "root") -> list[dict]:
        import requests
        query = f"'{folder_id}' in parents and trashed = false"
        params = {
            "q": query,
            "fields": "files(id,name,mimeType,size,modifiedTime)",
            "pageSize": 1000,
        }
        resp = requests.get(f"{API_BASE}/files", headers=self._headers(), params=params, timeout=30)
        if resp.status_code == 401:
            raise CloudProviderError("auth_expired", "Drive session expired; reconnect this account.")
        if resp.status_code == 403 and "quota" in resp.text.lower():
            raise CloudProviderError("quota_exceeded", "Drive API quota exceeded.")
        if resp.status_code != 200:
            raise CloudProviderError("provider_error", resp.text[:300])
        out = []
        for f in resp.json().get("files", []):
            is_dir = f.get("mimeType") == FOLDER_MIME
            out.append({
                "id": f["id"],
                "name": f["name"],
                "is_dir": is_dir,
                "size": None if is_dir else int(f.get("size", 0)),
                "modified": f.get("modifiedTime", ""),
                "mime_type": f.get("mimeType", ""),
            })
        return out

    def stream_file(self, file_id: str, range_header: str | None) -> StreamResult:
        import requests
        headers = self._headers()
        if range_header:
            headers["Range"] = range_header
        try:
            resp = requests.get(
                f"{API_BASE}/files/{file_id}",
                params={"alt": "media"},
                headers=headers,
                stream=True,
                timeout=30,
            )
        except requests.RequestException as e:
            return StreamResult(status=502, headers={}, chunks=None, error=str(e))

        if resp.status_code == 401:
            return StreamResult(status=401, headers={}, chunks=None, error="auth_expired")
        if resp.status_code == 403 and "quota" in resp.text.lower():
            return StreamResult(status=503, headers={}, chunks=None, error="quota_exceeded")
        if resp.status_code == 404:
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
