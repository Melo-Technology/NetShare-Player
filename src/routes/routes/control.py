"""LAN-only trusted-device endpoints for high-impact Server controls."""

from src.core.server_control import server_control
from ..tunnel import _uses_public_access_policy


class ControlRoutesMixin:
    def _control_guard(self) -> bool:
        # Deliberately identical to the write branch of cluster UNLINK's guard.
        if _uses_public_access_policy(self):
            self.send_error_json("Local network only", 403)
            return False
        if not self._has_device_credential():
            self.send_error_json("Trusted device required", 403)
            return False
        return True

    def _route_control_pause_indexing(self):
        if self._control_guard():
            self.send_json(server_control.pause_indexing())

    def _route_control_resume_indexing(self):
        if self._control_guard():
            self.send_json(server_control.resume_indexing())

    def _route_control_stop_sharing(self):
        if not self._control_guard():
            return
        result = server_control.stop_sharing()
        if result is None:
            return self.send_error_json("Server control unavailable", 503)
        self.send_json(result, status=202)
