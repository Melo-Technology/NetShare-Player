"""Google Drive read-only provider using installed-app OAuth 2.0 + PKCE.

Google's Desktop-app OAuth flow permits loopback redirects on 127.0.0.1 with a
random port and supports PKCE. Google documents ``client_secret`` as optional
for installed apps, but some Desktop OAuth client records still reject token
exchange/refresh without the secret. NetShare therefore accepts the secret as
an optional per-account credential and sends it only when supplied. PKCE remains
the proof binding the authorization code to the initiating process.

Only the ``drive.readonly`` scope is requested.  Provider error details exposed
to the desktop UI are deliberately sanitised; tokens, authorization codes and
PKCE material are never included in logs or error payloads.
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

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
API_BASE = "https://www.googleapis.com/drive/v3"
SCOPE = "https://www.googleapis.com/auth/drive.readonly"
FOLDER_MIME = "application/vnd.google-apps.folder"
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
    text = _SENSITIVE_ASSIGNMENT.sub(lambda m: f"{m.group(1)}=<redacted>", text)
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
            provider_message = str(payload.get("error_description") or "")
        elif isinstance(raw_error, dict):
            provider_code = str(raw_error.get("status") or raw_error.get("code") or "")
            provider_message = str(raw_error.get("message") or "")
            if not provider_code:
                errors = raw_error.get("errors")
                if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                    provider_code = str(errors[0].get("reason") or "")
    normalized_message = provider_message.lower().replace("-", "_")
    resolved_code = fallback_code
    if fallback_code == "token_exchange_failed" and "client_secret" in normalized_message and ("missing" in normalized_message or "required" in normalized_message):
        resolved_code = "client_secret_required"
        provider_message = (
            "This Google OAuth client requires its client secret. Enter the Client secret "
            "from the same Desktop OAuth client in Google Cloud Console, then try again."
        )
    safe_message = _safe_provider_message(provider_message, fallback_message)
    details = {
        "http_status": int(getattr(response, "status_code", 0) or 0),
    }
    if provider_code:
        details["provider_code"] = _safe_provider_message(provider_code, "provider_error")[:96]
    return CloudProviderError(resolved_code, safe_message, details=details)


def _require_access_token(payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("access_token"), str) or not payload["access_token"]:
        raise CloudProviderError(
            "token_response_invalid",
            "Google returned an invalid token response.",
        )
    return payload


def connect(client_id: str, label: str = "", timeout: int = 180, *, client_secret: str = "") -> dict:
    """Run the bounded interactive Desktop-app OAuth flow."""
    clean_client_id = str(client_id or "").strip()
    clean_client_secret = str(client_secret or "").strip()
    if not clean_client_id:
        raise CloudProviderError("client_id_required", "Google OAuth client ID is required.")
    if not HAS_REQUESTS:
        raise CloudProviderError(
            "missing_dependency",
            "Google Drive requires the 'requests' package (pip install requests).",
        )
    import requests

    verifier, challenge = generate_pkce_pair()
    oauth_state = generate_state()
    server, port = start_callback_server(expected_state=oauth_state)
    redirect_uri = f"http://127.0.0.1:{port}/"

    params = {
        "client_id": clean_client_id,
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
    if open_browser(auth_url) is False:
        server.server_close()
        raise CloudProviderError("browser_open_failed", "Could not open the browser for Google authorization.")

    result = wait_for_callback(server, timeout=timeout, expected_state=oauth_state)
    if not result:
        raise CloudProviderError("timeout", "No valid response from the browser consent screen before timeout.")
    if result.get("state", [""])[0] != oauth_state:
        # Defensive only: wait_for_callback already rejects mismatched state.
        raise CloudProviderError("state_mismatch", "OAuth state mismatch; the callback was rejected.")
    if "error" in result:
        provider_code = str(result.get("error", ["oauth_denied"])[0] or "oauth_denied")
        description = str(result.get("error_description", [""])[0] or "")
        raise CloudProviderError(
            "oauth_denied",
            _safe_provider_message(description, "Google authorization was denied."),
            details={"provider_code": _safe_provider_message(provider_code, "oauth_denied")[:96]},
        )
    code = result.get("code", [""])[0]
    if not code:
        raise CloudProviderError("no_code", "Authorization code missing from callback.")

    try:
        token_request = {
            "client_id": clean_client_id,
            "code": code,
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        if clean_client_secret:
            token_request["client_secret"] = clean_client_secret
        resp = requests.post(
            TOKEN_ENDPOINT,
            data=token_request,
            timeout=30,
        )
    except requests.RequestException as error:
        raise CloudProviderError(
            "network_error",
            "Could not reach Google's token endpoint.",
            details={"provider_code": type(error).__name__},
        ) from error
    if resp.status_code != 200:
        raise _response_error(
            resp,
            fallback_code="token_exchange_failed",
            fallback_message=f"Google rejected the token exchange (HTTP {resp.status_code}).",
        )
    try:
        payload = _require_access_token(resp.json())
    except ValueError as error:
        raise CloudProviderError("token_response_invalid", "Google returned invalid JSON from the token endpoint.") from error

    # Verify Drive API access using the already-authorized Drive scope.  This
    # catches disabled Drive API / project-policy errors before persisting an
    # account that cannot actually browse files, and also yields a useful label
    # without requesting an additional OpenID/userinfo scope.
    try:
        about = requests.get(
            f"{API_BASE}/about",
            params={"fields": "user(displayName,emailAddress)"},
            headers={"Authorization": f"Bearer {payload['access_token']}"},
            timeout=20,
        )
    except requests.RequestException as error:
        raise CloudProviderError(
            "network_error",
            "Authorization succeeded, but NetShare could not verify Google Drive access.",
            details={"provider_code": type(error).__name__},
        ) from error
    if about.status_code != 200:
        raise _response_error(
            about,
            fallback_code="drive_verification_failed",
            fallback_message=f"Google Drive access verification failed (HTTP {about.status_code}).",
        )
    try:
        about_payload = about.json()
    except ValueError as error:
        raise CloudProviderError("drive_response_invalid", "Google Drive returned an invalid verification response.") from error
    user = about_payload.get("user") if isinstance(about_payload, dict) else None
    user = user if isinstance(user, dict) else {}
    account_label = str(label or user.get("emailAddress") or user.get("displayName") or "Google Drive").strip()

    token_data = {
        "client_id": clean_client_id,
        "access_token": payload["access_token"],
        "refresh_token": str(payload.get("refresh_token") or ""),
        "expires_at": time.time() + float(payload.get("expires_in") or 3600),
        "label": account_label or "Google Drive",
    }
    if clean_client_secret:
        token_data["client_secret"] = clean_client_secret
    return token_data


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
        try:
            refresh_request = {
                "client_id": self._token_data["client_id"],
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
            client_secret = str(self._token_data.get("client_secret") or "").strip()
            if client_secret:
                refresh_request["client_secret"] = client_secret
            resp = requests.post(TOKEN_ENDPOINT, data=refresh_request, timeout=30)
        except requests.RequestException as error:
            raise CloudProviderError("network_error", "Could not refresh the Google Drive session.") from error
        if resp.status_code != 200:
            provider_error = _response_error(
                resp,
                fallback_code="auth_expired",
                fallback_message="Token refresh failed; reconnect this account.",
            )
            raise provider_error
        try:
            payload = _require_access_token(resp.json())
        except ValueError as error:
            raise CloudProviderError("auth_expired", "Google returned an invalid refresh response.") from error
        self._token_data["access_token"] = payload["access_token"]
        self._token_data["expires_at"] = time.time() + float(payload.get("expires_in") or 3600)

    def _headers(self) -> dict:
        self.refresh_if_needed()
        return {"Authorization": f"Bearer {self._token_data['access_token']}"}

    @staticmethod
    def _escape_query_literal(value: object) -> str:
        # Drive search literals use single quotes. Escape backslashes first so
        # a malicious/odd folder id cannot alter the query expression.
        return str(value or "root").replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def _classify_list_error(response) -> CloudProviderError:
        status = int(getattr(response, "status_code", 0) or 0)
        text = str(getattr(response, "text", "") or "").lower()
        provider = _response_error(
            response,
            fallback_code="provider_error",
            fallback_message=f"Google Drive returned HTTP {status} while listing files.",
        )
        provider_code = str(provider.details.get("provider_code") or "").lower()
        message = str(provider).lower()
        combined = " ".join((text, provider_code, message))
        if status == 401:
            return CloudProviderError(
                "auth_expired",
                "Drive session expired; reconnect this account.",
                details=provider.details,
            )
        if status == 404:
            return CloudProviderError(
                "not_found",
                "The requested Google Drive folder no longer exists or is not accessible.",
                details=provider.details,
            )
        if status == 429 or "ratelimit" in combined or "rate limit" in combined:
            return CloudProviderError(
                "rate_limited",
                "Google Drive is temporarily rate limiting requests. Try again shortly.",
                details=provider.details,
            )
        if status == 403:
            if "quota" in combined:
                return CloudProviderError(
                    "quota_exceeded",
                    "Drive API quota exceeded.",
                    details=provider.details,
                )
            if (
                "insufficient" in combined
                or "permission" in combined
                or "forbidden" in combined
            ):
                return CloudProviderError(
                    "permission_denied",
                    "Google Drive denied access to this folder. Reconnect the account and confirm the Drive read-only permission.",
                    details=provider.details,
                )
        if status in {500, 502, 503, 504}:
            return CloudProviderError(
                "provider_unavailable",
                "Google Drive is temporarily unavailable.",
                details=provider.details,
            )
        return provider

    def list_files_page(
        self, folder_id: str = "root", *, cursor: str | None = None, limit: int = 100,
    ) -> ListPage:
        import requests

        safe_folder_id = self._escape_query_literal(folder_id or "root")
        query = f"'{safe_folder_id}' in parents and trashed = false"
        page_size = max(1, min(int(limit or 100), 200))
        params = {
            "q": query,
            "spaces": "drive",
            "corpora": "user",
            "supportsAllDrives": "true",
            "includeItemsFromAllDrives": "true",
            "fields": "nextPageToken,files(id,name,mimeType,size,modifiedTime)",
            "pageSize": page_size,
        }
        if cursor:
            params["pageToken"] = str(cursor)

        resp = None
        last_error = None
        for attempt, delay in enumerate((0.0, 0.25, 0.75)):
            if delay:
                time.sleep(delay)
            try:
                resp = requests.get(
                    f"{API_BASE}/files",
                    headers=self._headers(),
                    params=params,
                    timeout=20,
                )
            except requests.RequestException as error:
                last_error = error
                if attempt < 2:
                    continue
                raise CloudProviderError(
                    "network_error",
                    "Could not reach Google Drive.",
                    details={"provider_code": type(error).__name__},
                ) from error
            if resp.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                continue
            break

        if resp is None:
            raise CloudProviderError(
                "network_error",
                "Could not reach Google Drive.",
                details={"provider_code": type(last_error).__name__ if last_error else "request_failed"},
            )
        if resp.status_code != 200:
            raise self._classify_list_error(resp)
        try:
            payload = resp.json()
        except ValueError as error:
            raise CloudProviderError("provider_error", "Google Drive returned invalid JSON.") from error
        if not isinstance(payload, dict):
            raise CloudProviderError("provider_error", "Google Drive returned an invalid file listing.")

        out: list[dict] = []
        for f in payload.get("files", []):
            if not isinstance(f, dict) or not f.get("id") or not f.get("name"):
                continue
            is_dir = f.get("mimeType") == FOLDER_MIME
            try:
                size = None if is_dir else int(f.get("size") or 0)
            except (TypeError, ValueError):
                size = 0
            out.append({
                "id": f["id"],
                "name": f["name"],
                "is_dir": is_dir,
                "size": size,
                "modified": f.get("modifiedTime", ""),
                "mime_type": f.get("mimeType", ""),
            })
        next_token = str(payload.get("nextPageToken") or "")
        return ListPage(items=out, next_cursor=next_token or None, has_more=bool(next_token))

    def list_files(self, folder_id: str = "root") -> list[dict]:
        """Legacy full-directory contract, implemented by bounded provider pages."""
        out: list[dict] = []
        cursor = None
        seen: set[str] = set()
        while True:
            page = self.list_files_page(folder_id, cursor=cursor, limit=200)
            out.extend(page.items)
            if not page.has_more or not page.next_cursor:
                return out
            if page.next_cursor in seen:
                raise CloudProviderError("provider_error", "Google Drive returned a repeated pagination token.")
            seen.add(page.next_cursor)
            cursor = page.next_cursor

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
            return StreamResult(status=502, headers={}, chunks=None, error="network_error")

        if resp.status_code == 401:
            return StreamResult(status=401, headers={}, chunks=None, error="auth_expired")
        if resp.status_code == 403 and "quota" in str(getattr(resp, "text", "")).lower():
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
