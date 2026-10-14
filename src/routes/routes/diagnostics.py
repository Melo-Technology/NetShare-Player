"""Authenticated LAN-only network diagnostic endpoints."""

from src.core.network_diagnostics import bounded_throughput_size, diagnostic_ping, throughput_chunks
from ..tunnel import _uses_public_access_policy


class DiagnosticRoutesMixin:
    def _route_diagnostic_ping(self):
        if _uses_public_access_policy(self):
            return self.send_error_json("Diagnostics are available on LAN only", 403)
        self.send_json(diagnostic_ping(), headers={"Cache-Control": "no-store"})

    def _route_diagnostic_throughput(self, params):
        # This bounded P5 primitive is also the single source for authenticated
        # adaptive-stream decisions over the tunnel. Manual ping stays LAN-only.
        size = bounded_throughput_size(params.get("bytes", [None])[0])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", size)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-NetShare-Diagnostic", "throughput")
        self.end_headers()
        try:
            for chunk in throughput_chunks(size):
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
