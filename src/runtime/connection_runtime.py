"""Connection telemetry and local QR helpers for the desktop UI.

This module is deliberately process-local and non-persistent. It does not alter
HTTP protocol behaviour or device credentials. WebSocket connect/disconnect
hooks only record the last time a client was seen so dashboard metrics remain
available after the client disconnects.
"""
from __future__ import annotations

import base64
import io
import threading
import time
from typing import Any


class ConnectionRuntimeController:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_connection_at: float | None = None

    def record_client_event(self) -> float:
        value = time.time()
        with self._lock:
            self._last_connection_at = value
        return value

    def last_connection_at(self) -> float | None:
        with self._lock:
            return self._last_connection_at

    @staticmethod
    def qr_available() -> bool:
        try:
            import qrcode  # noqa: F401
            from PIL import Image  # noqa: F401
            return True
        except Exception:
            return False

    def qr_data_url(self, payload: str) -> str | None:
        clean = str(payload or "").strip()
        if not clean or not self.qr_available():
            return None
        try:
            import qrcode

            qr = qrcode.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=7,
                border=4,
            )
            qr.add_data(clean)
            qr.make(fit=True)
            image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
            return f"data:image/png;base64,{encoded}"
        except Exception:
            return None


connection_runtime_controller = ConnectionRuntimeController()

__all__ = ["ConnectionRuntimeController", "connection_runtime_controller"]
