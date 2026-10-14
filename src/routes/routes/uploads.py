"""
File uploads: /upload plus the two-step approval flow
(/upload-request create + status poll).
"""

import json
import os
from pathlib import Path
from urllib.parse import unquote

import src.state as state
from src.core.content_policy import resolve_inbox_path, resolve_under_shared_root
from src.core.inbox import InboxService
from src.core.shared_paths import public_shared_path
from ..tunnel import _uses_public_access_policy

MAX_UPLOAD_BYTES = 512 * 1024 * 1024


class UploadRoutesMixin:

    def _route_upload_request_create(self):
        """Create an approval request or immediate upload grant for uploads."""
        if not state.FEATURE_FLAGS.get("upload"):
            return self.send_error_json("Upload disabled", 403)

        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_error_json("Invalid JSON body", 400)

        filename = str(payload.get("filename", "")).strip()
        try:
            size = int(payload.get("size", 0))
        except (TypeError, ValueError):
            size = 0
        if not filename or Path(filename).name != filename or filename in (".", ".."):
            return self.send_error_json("Invalid filename", 400)
        if size < 0:
            return self.send_error_json("Invalid size", 400)

        via_tunnel = _uses_public_access_policy(self)
        max_bytes = (
            max(1, int(state.MAX_UPLOAD_SIZE_MB)) * 1024 * 1024
            if via_tunnel else MAX_UPLOAD_BYTES
        )
        if size > max_bytes:
            return self.send_error_json("Request body too large", 413)
        if via_tunnel and state.ALLOWED_UPLOAD_EXTENSIONS:
            if Path(filename).suffix.lower() not in state.ALLOWED_UPLOAD_EXTENSIONS:
                return self.send_error_json("File type not allowed", 415)

        if state.PUBLIC_UPLOAD_MODE != "request":
            token = state.issue_public_upload_grant(
                filename, size, self._client_ip(), "/incoming"
            )
            return self.send_json({"status": "accepted", "upload_token": token})

        request = state.create_public_upload_request(
            filename, size, self._client_ip(), "/incoming"
        )
        self.send_json({
            "status": request["status"],
            "request_id": request["id"],
            "expires_at": request["expires_at"],
        }, 202)

    def _route_upload_request_status(self, params):
        request_id = params.get("id", [""])[0].strip()
        if not request_id:
            return self.send_error_json("Missing request id", 400)
        request = state.get_public_upload_request(request_id)
        if not request:
            return self.send_error_json("Request not found", 404)
        payload = {
            "status": request.get("status", "pending"),
            "request_id": request_id,
        }
        if request.get("status") == "accepted":
            payload["upload_token"] = request.get("token", "")
        self.send_json(payload)

    def _route_upload(self, params):
        """Receive a file upload and persist it under the configured Inbox."""
        if not state.FEATURE_FLAGS.get("upload"):
            return self.send_error_json("Upload disabled", 403)

        via_tunnel = _uses_public_access_policy(self)
        role = self._public_role()
        client_ip = self._client_ip()
        if via_tunnel and role == "community":
            if not state.upload_allowed_for_ip(client_ip):
                state._record_write_activity("rate-limit", "public upload", None, client_ip)
                return self.send_error_json("Upload rate limit exceeded", 429)

        filename = (
            params.get("filename", [""])[0]
            or unquote(self.headers.get("X-Filename", ""))
        ).strip()
        if not filename:
            return self.send_error_json("Missing filename", 400)
        if Path(filename).name != filename or filename in (".", ".."):
            return self.send_error_json("Invalid filename", 400)
        if via_tunnel and state.ALLOWED_UPLOAD_EXTENSIONS:
            if Path(filename).suffix.lower() not in state.ALLOWED_UPLOAD_EXTENSIONS:
                return self.send_error_json("File type not allowed", 415)

        resolved_folder = resolve_inbox_path(state.INBOX_DIR, "/")
        if resolved_folder is None:
            return self.send_error_json("Invalid upload directory", 500)
        folder = resolved_folder.path
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            state._emit(f"UPLOAD directory unavailable ({type(error).__name__})", "error")
            return self.send_error_json(
                "Upload directory unavailable", 500,
                code="transfer.upload_directory_unavailable", domain="transfer",
                support_code="XFER-05",
            )
        if not folder.is_dir():
            return self.send_error_json("Target directory not found", 404)

        length = self._content_length()
        if length is None:
            return
        max_bytes = (
            max(1, int(state.MAX_UPLOAD_SIZE_MB)) * 1024 * 1024
            if via_tunnel else MAX_UPLOAD_BYTES
        )
        if length > max_bytes:
            return self.send_error_json("Request body too large", 413)
        if state.PUBLIC_UPLOAD_MODE == "request":
            token = self.headers.get("X-Upload-Token", "").strip()
            if not state.consume_public_upload_grant(token, filename, length):
                return self.send_error_json("Upload request approval required", 403)

        overwrite = params.get("overwrite", ["0"])[0].lower() in ("1", "true", "yes")
        target = resolve_under_shared_root(folder, filename)
        if target is None:
            return self.send_error_json("Invalid destination", 403)
        if target.exists() and not overwrite:
            target = self._unique_upload_path(target)

        transfer_id = f"legacy-{client_ip}-{os.getpid()}-{id(self)}"
        try:
            from src.runtime.activity_runtime import activity_runtime
            activity_runtime.publish_transfer({
                "id": transfer_id,
                "filename": filename,
                "file_count": 1,
                "total_bytes": length,
                "received_bytes": 0,
                "progress": 0.0,
                "status": "receiving",
                "client": client_ip,
            })
        except Exception:
            pass

        try:
            relative = "/" + str(target.relative_to(state.INBOX_DIR.resolve())).replace("\\", "/")
            rel_path = f"/@inbox{relative}"
            state._record_write_activity("receiving", rel_path, length, client_ip)
            with open(target, "wb") as f:
                remaining = length
                received = 0
                while remaining > 0:
                    chunk = self.rfile.read(min(self._CHUNK, remaining))
                    if not chunk:
                        raise OSError("Connection closed before upload completed")
                    f.write(chunk)
                    remaining -= len(chunk)
                    received += len(chunk)
                    try:
                        activity_runtime.publish_transfer({
                            "id": transfer_id,
                            "received_bytes": received,
                            "progress": received / length if length else 1.0,
                            "status": "receiving",
                            "client": client_ip,
                        })
                    except Exception:
                        pass
            if via_tunnel:
                state.record_upload_for_ip(client_ip)
                state.PUBLIC_UPLOAD_STATS["received"] += 1
            state._record_write_activity("received", rel_path, target.stat().st_size, client_ip)
            history_recorded = InboxService(
                state.INBOX_DIR, state.INBOX_HISTORY_PATH,
            ).record_received(relative, target.stat().st_size, source=client_ip)
            if not history_recorded:
                state._emit("INBOX history full; reception kept without automatic purge", "error")
            try:
                activity_runtime.publish_transfer({
                    "id": transfer_id,
                    "path": rel_path,
                    "received_bytes": length,
                    "progress": 1.0,
                    "status": "completed",
                    "client": client_ip,
                })
            except Exception:
                pass
            if state._ws_manager:
                state._ws_manager.notify_file_change("/")
            self.send_json({
                "ok": True,
                "path": rel_path,
                "size": target.stat().st_size,
                "overwritten": overwrite,
            }, 201)
        except PermissionError:
            try:
                activity_runtime.publish_transfer({"id": transfer_id, "status": "failed", "client": client_ip})
            except Exception:
                pass
            self.send_error_json("Permission denied", 403)
        except OSError as error:
            try:
                activity_runtime.publish_transfer({"id": transfer_id, "status": "failed", "client": client_ip})
            except Exception:
                pass
            state._emit(f"UPLOAD failed ({type(error).__name__})", "error")
            self.send_error_json(
                "Upload failed", 500, code="transfer.upload_failed",
                domain="transfer", support_code="XFER-05",
            )

    def _unique_upload_path(self, target: Path) -> Path:
        stem = target.stem
        suffix = target.suffix
        parent = target.parent
        for i in range(1, 10_000):
            candidate = parent / f"{stem} ({i}){suffix}"
            if not candidate.exists():
                return candidate
        return parent / f"{stem} ({os.getpid()}){suffix}"

    def _notify_written_file(self, target: Path, *, root_slot="slot-1", root=None):
        try:
            from src.core.file_index import _file_index
            root = Path(root or state.root_for_slot(root_slot))
            _file_index.add_file(target, root, root_slot)
            if state._ws_manager:
                relative = "/" + str(target.relative_to(root)).replace("\\", "/")
                rel = public_shared_path(root_slot, relative)
                state._ws_manager.notify_file_change(rel)
        except Exception:
            pass
