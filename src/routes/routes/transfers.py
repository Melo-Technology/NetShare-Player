"""API v2 resumable multi-file transfer routes."""

import json
import threading
from pathlib import Path
from urllib.parse import unquote

import src.state as state
from src.core.transfer_sessions import CHUNK_SIZE, TransferError, TransferSessionStore
from src.core.content_policy import resolve_inbox_path
from src.core.inbox import InboxService
from ..tunnel import _uses_public_access_policy


_stores: dict[tuple[str, str], TransferSessionStore] = {}
_stores_lock = threading.Lock()


def _store() -> TransferSessionStore:
    key = (str(state.INBOX_DIR.resolve()), "inbox")
    with _stores_lock:
        return _stores.setdefault(key, TransferSessionStore(
            state.INBOX_DIR.parent, state.INBOX_DIR.name,
            virtual_prefix="/@inbox",
        ))


def _manifest_summary(manifest: list[dict]) -> tuple[str, int, int]:
    """Validate the manifest before an approval request and summarize it safely."""
    items = _store().validate_manifest(manifest)
    total = sum(item.size for item in items)
    label = items[0].filename if len(items) == 1 else f"{len(items)} files"
    return label, total, len(items)


def _progress(metadata: dict) -> tuple[int, int, float]:
    total = 0
    received = 0
    chunk_size = max(1, int(metadata.get("chunk_size") or CHUNK_SIZE))
    for item in metadata.get("items") or []:
        size = max(0, int(item.get("size") or 0))
        total += size
        count = max(1, (size + chunk_size - 1) // chunk_size)
        for index in set(item.get("received_chunks") or []):
            try:
                idx = int(index)
            except (TypeError, ValueError):
                continue
            if idx < 0 or idx >= count:
                continue
            start = idx * chunk_size
            received += max(0, min(chunk_size, size - start))
    ratio = 1.0 if total == 0 and metadata.get("status") == "committed" else (
        min(1.0, received / total) if total > 0 else 0.0
    )
    return received, total, ratio


def _publish_transfer(metadata: dict, *, client: str, status: str | None = None, path: str = "") -> None:
    try:
        from src.runtime.activity_runtime import activity_runtime
        received, total, ratio = _progress(metadata)
        items = metadata.get("items") or []
        filename = str(items[0].get("filename") or "") if len(items) == 1 else f"{len(items)} files"
        final_status = str(status or metadata.get("status") or "receiving")
        if final_status in {"committed", "completed"}:
            ratio = 1.0
            received = total
            final_status = "completed"
        activity_runtime.publish_transfer({
            "id": str(metadata.get("id") or ""),
            "filename": filename,
            "file_count": max(1, len(items)),
            "total_bytes": total,
            "received_bytes": received,
            "progress": ratio,
            "status": final_status,
            "client": client,
            "path": path,
        })
    except Exception:
        # Transfer correctness cannot depend on desktop observability.
        pass


class TransferRoutesMixin:
    def _send_transfer_error(self, error: TransferError):
        self.send_error_json(
            str(error), error.status, code=error.code, domain=error.domain,
            support_code=error.support_code,
        )

    def _transfer_owner(self) -> str:
        return self._device_id() or f"ip:{self.client_address[0]}"

    def _route_transfer_create(self):
        body = self._read_body(128 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            manifest = payload.get("items") if isinstance(payload, dict) else None
            label, total, file_count = _manifest_summary(manifest)

            if _uses_public_access_policy(self):
                if not isinstance(manifest, list):
                    raise TransferError("Invalid transfer manifest")
                for item in manifest:
                    suffix = Path(str(item.get("filename", ""))).suffix.lower()
                    if state.ALLOWED_UPLOAD_EXTENSIONS and suffix not in state.ALLOWED_UPLOAD_EXTENSIONS:
                        raise TransferError("File type not allowed", 415)
                max_bytes = max(1, int(state.MAX_UPLOAD_SIZE_MB)) * 1024 * 1024
                if total > max_bytes:
                    raise TransferError("Transfer is too large", 413)

            # "Ask first" is a receive policy, not only a public-tunnel policy.
            # Reuse the established one-time upload grant instead of adding a
            # second approval protocol for trusted Player transfers.
            if state.PUBLIC_UPLOAD_MODE == "request":
                token = self.headers.get("X-Upload-Token", "").strip()
                if token:
                    if not state.consume_public_upload_grant(token, label, total):
                        raise TransferError("Transfer approval is invalid or expired", 403)
                else:
                    request = state.create_public_upload_request(
                        label, total, self._client_ip(), "/@inbox"
                    )
                    return self.send_json({
                        "status": request["status"],
                        "request_id": request["id"],
                        "expires_at": request["expires_at"],
                        "file_count": file_count,
                    }, 202)

            result = _store().create(manifest, self._transfer_owner())
            _publish_transfer(result, client=self._client_ip(), status="receiving")
            self.send_json(result, 201)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error_json("Invalid JSON body", 400)
        except TransferError as error:
            self._send_transfer_error(error)

    def _route_transfer_get(self, session_id: str):
        try:
            self.send_json(_store().get(session_id, self._transfer_owner()))
        except TransferError as error:
            self._send_transfer_error(error)

    def _route_transfer_chunk(self, session_id: str, item_id: str, chunk_index: str):
        try:
            index = int(chunk_index)
        except ValueError:
            return self.send_error_json("Invalid chunk index", 400)
        body = self._read_body(CHUNK_SIZE, allow_empty=True)
        if body is None:
            return
        try:
            result = _store().put_chunk(
                session_id,
                unquote(item_id),
                index,
                body,
                self._transfer_owner(),
            )
            _publish_transfer(result, client=self._client_ip(), status="receiving")
            self.send_json(result)
        except TransferError as error:
            try:
                from src.runtime.activity_runtime import activity_runtime
                activity_runtime.publish_transfer({
                    "id": session_id, "status": "failed", "client": self._client_ip(),
                })
            except Exception:
                pass
            self._send_transfer_error(error)

    def _route_transfer_commit(self, session_id: str):
        body = self._read_body(8 * 1024, allow_empty=True)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
            result = _store().commit(
                session_id,
                self._transfer_owner(),
                overwrite=payload.get("overwrite") is True,
            )
            final_path = ""
            service = InboxService(state.INBOX_DIR, state.INBOX_HISTORY_PATH)
            for path in result.get("paths", []):
                prefix = "/@inbox/"
                resolved = (
                    resolve_inbox_path(state.INBOX_DIR, path[len(prefix):], require_file=True)
                    if path.startswith(prefix) else None
                )
                if resolved is None or not resolved.path.is_file():
                    raise TransferError("Invalid committed path", 500)
                target = resolved.path
                final_path = path
                state._record_write_activity(
                    "received", path, target.stat().st_size, self.client_address[0]
                )
                recorded = service.record_received(
                    str(target.relative_to(state.INBOX_DIR.resolve())), target.stat().st_size,
                    source=self.client_address[0],
                )
                if not recorded:
                    state._emit("INBOX history full; reception kept without automatic purge", "error")
            _publish_transfer(result, client=self._client_ip(), status="completed", path=final_path)
            # Any connected Player may currently be viewing the Inbox.  A root
            # invalidation is intentionally broad and cheap; each Player decides
            # locally whether its current path needs reloading.
            if state._ws_manager:
                state._ws_manager.notify_file_change("/")
            self.send_json(result)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error_json("Invalid JSON body", 400)
        except TransferError as error:
            try:
                from src.runtime.activity_runtime import activity_runtime
                activity_runtime.publish_transfer({
                    "id": session_id, "status": "failed", "client": self._client_ip(),
                })
            except Exception:
                pass
            self._send_transfer_error(error)
        except OSError as error:
            try:
                from src.runtime.activity_runtime import activity_runtime
                activity_runtime.publish_transfer({
                    "id": session_id, "status": "failed", "client": self._client_ip(),
                })
            except Exception:
                pass
            state._emit(
                f"TRANSFER commit failed ({type(error).__name__})", "error"
            )
            self.send_error_json(
                "Transfer failed", 500, code="transfer.commit_failed",
                domain="transfer", support_code="XFER-05",
            )

    def _route_transfer_delete(self, session_id: str):
        try:
            _store().delete(session_id, self._transfer_owner())
            try:
                from src.runtime.activity_runtime import activity_runtime
                activity_runtime.publish_transfer({
                    "id": session_id, "status": "cancelled", "client": self._client_ip(),
                })
            except Exception:
                pass
            self.send_json({"ok": True})
        except TransferError as error:
            self._send_transfer_error(error)
