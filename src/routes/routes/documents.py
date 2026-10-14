"""Text-document reading and inline editing through ``/document``."""

import json
from pathlib import Path

import src.state as state
from src.core.shared_paths import resolve_shared_path
from .ping import _TEXT_EDIT_EXTS

MAX_TEXT_EDIT_BYTES = 2 * 1024 * 1024


class DocumentRoutesMixin:

    def _route_document_get(self, params):
        resolved = self._editable_document_target(params)
        if resolved is None:
            return
        target = resolved.path
        try:
            if target.stat().st_size > MAX_TEXT_EDIT_BYTES:
                return self.send_error_json("Document too large for inline edit", 413)
            raw = target.read_bytes()
            text = raw.decode("utf-8-sig")
            self.send_json({
                "path": resolved.virtual_path,
                "name": target.name,
                "encoding": "utf-8",
                "content": text,
            })
        except UnicodeDecodeError:
            self.send_error_json("Document is not UTF-8 text", 415)
        except PermissionError:
            self.send_error_json("Permission denied", 403)
        except OSError as error:
            state._emit(f"DOCUMENT read failed ({type(error).__name__})", "error")
            self.send_error_json(
                "Document read failed", 500, code="storage.document_read_failed",
                domain="storage", support_code="STOR-03",
            )

    def _route_document_put(self, params):
        if not state.FEATURE_FLAGS.get("document_edit"):
            return self.send_error_json("Document edit disabled", 403)
        resolved = self._editable_document_target(params)
        if resolved is None:
            return
        target = resolved.path
        body = self._read_body(MAX_TEXT_EDIT_BYTES, allow_empty=True)
        if body is None:
            return
        content_type = self.headers.get("Content-Type", "")
        try:
            if "application/json" in content_type:
                payload = json.loads(body.decode("utf-8"))
                text = str(payload.get("content", ""))
            else:
                text = body.decode("utf-8")
            with open(target, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            self._notify_written_file(target, root_slot=resolved.slot, root=resolved.root)
            state._record_write_activity(
                "edited",
                resolved.virtual_path,
                target.stat().st_size,
                self.client_address[0],
            )
            self.send_json({
                "ok": True,
                "path": resolved.virtual_path,
                "size": target.stat().st_size,
            })
        except UnicodeDecodeError:
            self.send_error_json("Document body must be UTF-8 text", 415)
        except json.JSONDecodeError:
            self.send_error_json("Invalid JSON body", 400)
        except PermissionError:
            self.send_error_json("Permission denied", 403)
        except OSError as error:
            state._emit(f"DOCUMENT save failed ({type(error).__name__})", "error")
            self.send_error_json(
                "Document save failed", 500, code="storage.document_save_failed",
                domain="storage", support_code="STOR-04",
            )

    def _editable_document_target(self, params) -> Path | None:
        rel = params.get("path", [""])[0]
        if not rel:
            self.send_error_json("Missing 'path' parameter", 400)
            return None
        resolved = resolve_shared_path(rel, visible=True)
        if resolved is None:
            self.send_error_json("Document not found", 404)
            return None
        lock = self._lock_status(rel)
        if lock["locked"]:
            self._send_premium_locked(lock)
            return None
        target = resolved.path
        if not target.exists():
            self.send_error_json("Document not found", 404)
            return None
        if not target.is_file():
            self.send_error_json("Not a file", 400)
            return None
        if target.suffix.lower() not in _TEXT_EDIT_EXTS:
            self.send_error_json(
                "Only text-like documents can be edited inline; use /upload to replace office files",
                415,
            )
            return None
        return resolved
