"""Trusted Player routes for previewing and manually importing Inbox files."""

import json

import src.state as state
from src.core.inbox import InboxService


def _service() -> InboxService:
    return InboxService(state.INBOX_DIR, state.INBOX_HISTORY_PATH)


class InboxRoutesMixin:
    def _inbox_guard(self):
        if not self._has_full_write_access():
            self.send_error_json("Trusted device or admin key required", 403)
            return False
        return True

    def _route_inbox(self):
        if self._inbox_guard():
            service = _service()
            self.send_json({
                "items": service.list_items(),
                "history": service.history(),
                "history_capacity": service.history_capacity(),
            })

    def _route_inbox_import(self):
        if not self._inbox_guard():
            return
        body = self._read_body(32 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            result = _service().import_file(
                str(payload.get("path", "")),
                destination_slot=str(payload.get("destination_slot", "")),
                destination_path=str(payload.get("destination_path", "/")),
            )
            # The Inbox catalogue is filesystem-backed, but shared-folder lists
            # are index-backed. Update the index before broadcasting the change
            # so other connected Players cannot refresh into stale data.
            try:
                from pathlib import Path
                from src.core.file_index import _file_index
                root = Path(state.root_for_slot(result["slot"])).resolve()
                target = (root / str(result["path"]).lstrip("/\\")).resolve()
                _file_index.add_file(target, root, str(result["slot"]))
            except Exception as error:
                state._emit(f"INBOX index update failed ({type(error).__name__})", "error")
            if state._ws_manager:
                # Root invalidation intentionally reaches Players viewing any
                # shared subfolder; each client decides whether to reload.
                state._ws_manager.notify_file_change("/")
            self.send_json({"imported": True, **result})
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.send_error_json("Invalid Inbox import", 400)
        except FileNotFoundError as error:
            self.send_error_json(str(error), 404)
        except OSError as error:
            state._emit(f"INBOX import failed ({type(error).__name__})", "error")
            self.send_error_json(
                "Inbox import failed", 500, code="transfer.inbox_import_failed",
                domain="transfer", support_code="XFER-06",
            )

    def _route_inbox_history_purge(self):
        if self._inbox_guard():
            self.send_json({"purged": _service().purge_history()})
