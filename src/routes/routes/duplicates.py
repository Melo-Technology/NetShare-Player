"""LAN-only administrative duplicate scan endpoints."""

import src.state as state
from src.core.content_policy import INBOX_SLOT
from src.core.duplicate_detector import DuplicateDetector, DuplicateScanRoot
from ..tunnel import _uses_public_access_policy


duplicate_detector = DuplicateDetector()


class DuplicateRoutesMixin:
    def _duplicate_guard(self) -> bool:
        if _uses_public_access_policy(self):
            self.send_error_json("Local network only", 403)
            return False
        if not self._has_full_write_access():
            self.send_error_json("Trusted device or admin key required", 403)
            return False
        return True

    def _route_duplicates(self):
        if self._duplicate_guard():
            self.send_json(duplicate_detector.snapshot())

    def _route_duplicate_scan(self):
        if not self._duplicate_guard():
            return
        # Inbox is first so an unlikely physical overlap with a broadly selected
        # shared root retains the dedicated storage identity exactly once.
        roots = (DuplicateScanRoot(INBOX_SLOT, state.INBOX_DIR),) + tuple(
            DuplicateScanRoot(root.slot, root.path) for root in state.SHARED_ROOTS
        )
        if not duplicate_detector.start(roots):
            return self.send_error_json("Duplicate scan already running", 409)
        self.send_json(duplicate_detector.snapshot(), 202)
