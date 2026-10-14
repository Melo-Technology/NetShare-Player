"""Ticket issuance and credential-free downloads for NetShare Web."""

import json
from pathlib import PurePosixPath
from urllib.parse import quote

import src.state as state
from src.core.embedded_tracks import (
    EmbeddedTrackError, SubtitleFailure, extract_webvtt, probe_hls_tracks,
)
from src.core.shared_paths import resolve_shared_path
from src.core.web_sessions import rfc3339


class WebDownloadRoutesMixin:
    _AUDIO_EXTENSIONS = {
        ".aac", ".flac", ".m4a", ".mp3", ".oga", ".ogg", ".opus",
        ".wav", ".webm", ".wma",
    }
    _VIDEO_EXTENSIONS = {
        ".3gp", ".avi", ".m4v", ".mkv", ".mov", ".mp4", ".mpeg",
        ".mpg", ".ogv", ".ts", ".webm", ".wmv",
    }

    def _probe_web_cluster_path(self, requested: str, session_id: str):
        cluster_path = self._parse_cluster_virtual_path(requested)
        if not cluster_path:
            return None, None
        return cluster_path, self._probe_cluster_virtual_file(
            *cluster_path, web_session_id=session_id,
        )

    def _route_web_download_ticket_create(self):
        lookup = self._web_session_lookup()
        if lookup.status != "valid":
            return self._send_web_session_error(lookup.status)
        if not self._enforce_web_rate("download-ticket", lookup.session.id, 30, 60):
            return
        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            requested = str(payload.get("path", ""))
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            return self.send_error_json("Invalid ticket request", 400)
        cluster_path, cluster_probe = self._probe_web_cluster_path(
            requested, lookup.session.id,
        )
        if cluster_path:
            if cluster_probe is None:
                return self.send_error_json("File not found", 404)
            etag = str(cluster_probe.headers.get("ETag", ""))
            size = int(cluster_probe.length)
            if not etag or size < 0:
                return self.send_error_json("File not found", 404)
        else:
            resolved = resolve_shared_path(requested, visible=True, require_file=True)
            target = resolved.path if resolved else None
            if target is None or not target.is_file():
                return self.send_error_json("File not found", 404)
            lock = self._lock_status(requested)
            if lock["locked"]:
                return self._send_premium_locked(lock)
            etag = self._file_etag(target)
            size = target.stat().st_size
        token, grant = state.WEB_DOWNLOAD_TICKET_STORE.issue(
            session_id=lookup.session.id,
            generation=lookup.session.generation,
            path=requested,
            etag=etag,
            size=size,
        )
        host = self.headers.get("Host", "").strip()
        download_path = f"/api/v2/web/download/{quote(token, safe='')}"
        download_url = f"https://{host}{download_path}" if host else download_path
        return self.send_json({
            "ticket_id": token,
            "download_url": download_url,
            "expires_at": rfc3339(grant.ticket_expires_at),
            "etag": etag,
            "size": size,
        }, 201, headers=self._web_no_store_headers())

    def _route_web_download(self, token: str):
        authorization = state.WEB_DOWNLOAD_TICKET_STORE.authorize(
            token,
            generation=state.WEB_CREDENTIAL_GENERATION,
            session_active=state.WEB_SESSION_STORE.is_active_id,
        )
        if authorization.status != "valid":
            status = 410 if authorization.status in ("expired", "exhausted") else 404
            code = (
                "web.download.expired_ticket" if status == 410
                else "web.download.invalid_ticket"
            )
            return self.send_error_json(
                "Download ticket unavailable", status, code=code,
                domain="web.download", headers=self._web_no_store_headers(),
            )
        grant = authorization.grant
        cluster_path, cluster_probe = self._probe_web_cluster_path(
            grant.path, grant.session_id,
        )
        if cluster_path:
            invalid = (
                cluster_probe is None
                or str(cluster_probe.headers.get("ETag", "")) != grant.etag
                or int(cluster_probe.length) != grant.size
            )
        else:
            resolved = resolve_shared_path(grant.path, visible=True, require_file=True)
            target = resolved.path if resolved else None
            invalid = (
                target is None or not target.is_file()
                or self._file_etag(target) != grant.etag
                or target.stat().st_size != grant.size
                or self._lock_status(grant.path)["locked"]
            )
        if invalid:
            return self.send_error_json(
                "Download ticket unavailable", 404,
                code="web.download.invalid_ticket", domain="web.download",
                headers=self._web_no_store_headers(),
            )
        if not state.WEB_DOWNLOAD_TICKET_STORE.acquire_stream(grant.session_id):
            return self.send_error_json(
                "Too many concurrent downloads", 429,
                code="web.download.concurrency_limit", domain="web.download",
                headers={**self._web_no_store_headers(), "Retry-After": "1"},
            )
        try:
            self._download_attachment = True
            return self._route_file(
                {"path": [grant.path]},
                cluster_web_session_id=grant.session_id if cluster_path else "",
            )
        finally:
            self._download_attachment = False
            state.WEB_DOWNLOAD_TICKET_STORE.release_stream(grant.session_id)

    def _route_web_media_grant_create(self):
        lookup = self._web_session_lookup()
        if lookup.status != "valid":
            return self._send_web_session_error(lookup.status)
        if not self._enforce_web_rate("media-grant", lookup.session.id, 60, 60):
            return
        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            requested = str(payload.get("path", ""))
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            return self.send_error_json("Invalid media grant request", 400)
        cluster_path, cluster_probe = self._probe_web_cluster_path(
            requested, lookup.session.id,
        )
        if cluster_path:
            suffix = PurePosixPath(cluster_path[1]).suffix.lower()
            if (
                cluster_probe is None
                or suffix not in self._AUDIO_EXTENSIONS | self._VIDEO_EXTENSIONS
            ):
                return self.send_error_json("Media file not found", 404)
            target = None
            etag = str(cluster_probe.headers.get("ETag", ""))
            size = int(cluster_probe.length)
            if not etag or size < 0:
                return self.send_error_json("Media file not found", 404)
        else:
            resolved = resolve_shared_path(requested, visible=True, require_file=True)
            target = resolved.path if resolved else None
            if (target is None or not target.is_file()
                    or target.suffix.lower() not in self._AUDIO_EXTENSIONS | self._VIDEO_EXTENSIONS):
                return self.send_error_json("Media file not found", 404)
            lock = self._lock_status(requested)
            if lock["locked"]:
                return self._send_premium_locked(lock)
            etag = self._file_etag(target)
            size = target.stat().st_size
        origin = self.headers.get("Origin", "").strip()
        if not origin or not self._is_allowed_cors_origin():
            return self.send_error_json("Browser origin required", 403)
        token, grant = state.WEB_MEDIA_GRANT_STORE.issue(
            session_id=lookup.session.id, generation=lookup.session.generation,
            path=requested, origin=origin, etag=etag, size=size,
        )
        host = self.headers.get("Host", "").strip()
        media_path = f"/api/v2/web/media/{quote(token, safe='')}"
        media_url = f"https://{host}{media_path}" if host else media_path
        tracks = {"video": [], "audio": [], "subtitles": []}
        requires_hls = False
        if target is not None and target.suffix.lower() in self._VIDEO_EXTENSIONS:
            try:
                inventory = probe_hls_tracks(target)
                tracks = inventory.as_json()
                requires_hls = inventory.requires_hls(target)
            except EmbeddedTrackError:
                requires_hls = True
        return self.send_json({
            "media_url": media_url,
            "expires_at": rfc3339(grant.expires_at),
            "tracks": tracks,
            "playback": {
                "requires_hls": requires_hls,
                "cluster_relay": bool(cluster_path),
                "direct_play_only": bool(cluster_path),
            },
        }, 201, headers=self._web_no_store_headers())

    def _route_web_media(self, token: str):
        origin = self.headers.get("Origin", "").strip()
        grant = state.WEB_MEDIA_GRANT_STORE.authorize(
            token, generation=state.WEB_CREDENTIAL_GENERATION, origin=origin,
            session_active=state.WEB_SESSION_STORE.is_active_id,
        )
        if grant is None:
            return self.send_error_json(
                "Media grant unavailable", 404, code="web.media.invalid_grant",
                domain="web.media", headers=self._web_no_store_headers(),
            )
        cluster_path, cluster_probe = self._probe_web_cluster_path(
            grant.path, grant.session_id,
        )
        if cluster_path:
            invalid = (
                cluster_probe is None
                or str(cluster_probe.headers.get("ETag", "")) != grant.etag
                or int(cluster_probe.length) != grant.size
            )
        else:
            resolved = resolve_shared_path(grant.path, visible=True, require_file=True)
            target = resolved.path if resolved else None
            invalid = (
                target is None or not target.is_file()
                or self._file_etag(target) != grant.etag
                or target.stat().st_size != grant.size
                or self._lock_status(grant.path)["locked"]
            )
        if invalid:
            return self.send_error_json(
                "Media grant unavailable", 404, code="web.media.invalid_grant",
                domain="web.media", headers=self._web_no_store_headers(),
            )
        self._download_attachment = False
        return self._route_file(
            {"path": [grant.path]},
            cluster_web_session_id=grant.session_id if cluster_path else "",
        )

    def _route_web_media_subtitle(self, token: str, stream_index: str):
        origin = self.headers.get("Origin", "").strip()
        grant = state.WEB_MEDIA_GRANT_STORE.authorize(
            token, generation=state.WEB_CREDENTIAL_GENERATION, origin=origin,
            session_active=state.WEB_SESSION_STORE.is_active_id,
        )
        if grant is None:
            state._emit("SUBTITLE  unavailable reason=grant_invalid_or_expired", "error")
            return self.send_error_json("Media grant unavailable", 404)
        if self._parse_cluster_virtual_path(grant.path):
            state._emit("SUBTITLE  unavailable reason=cluster_direct_play_only", "info")
            return self.send_error_json("Subtitle track unavailable", 404)
        resolved = resolve_shared_path(grant.path, visible=True, require_file=True)
        target = resolved.path if resolved else None
        try:
            changed = (target is None or not target.is_file()
                       or self._file_etag(target) != grant.etag
                       or target.stat().st_size != grant.size)
        except OSError:
            changed = True
        if changed:
            state._emit("SUBTITLE  unavailable reason=file_changed", "error")
            return self.send_error_json("Media grant unavailable", 404)
        if self._lock_status(grant.path)["locked"]:
            state._emit("SUBTITLE  unavailable reason=grant_invalid_or_expired", "error")
            return self.send_error_json("Media grant unavailable", 404)
        try:
            payload = extract_webvtt(target, int(stream_index))
        except ValueError:
            state._emit("SUBTITLE  unavailable reason=track_absent", "error")
            return self.send_error_json("Subtitle track unavailable", 404)
        except EmbeddedTrackError as error:
            # Only fixed diagnostic codes: never serialize exception text or request data.
            reason = error.reason if isinstance(error.reason, SubtitleFailure) else SubtitleFailure.EXTRACTION_FAILED
            state._emit(f"SUBTITLE  unavailable reason={reason.value}", "error")
            return self.send_error_json("Subtitle track unavailable", 404)
        self.send_response(200)
        self.send_header("Content-Type", "text/vtt; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "private, no-store")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)
