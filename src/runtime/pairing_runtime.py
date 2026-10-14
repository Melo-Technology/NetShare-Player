"""Shared local trusted-device pairing runtime.

This controller is intentionally thin: it delegates credential semantics to the
existing ``src.state`` functions and only exposes a UI-neutral snapshot.  It
allows Tkinter and the future WebView to share the same one-time-code lifecycle
without duplicating state or changing the persisted trusted-device schema.
"""
from __future__ import annotations

import base64
import io
import time
from typing import Any


class PairingRuntimeError(RuntimeError):
    pass


class PairingRuntimeController:
    def __init__(self, state_module=None):
        if state_module is None:
            import src.state as state_module
        self._state = state_module

    def provisioning_uri(self) -> str:
        s = self._state
        return str(
            s.pyotp.TOTP(s.TOTP_SECRET).provisioning_uri(
                name=s.SERVER_NAME,
                issuer_name="NetShare Server",
            )
        )

    def snapshot(self) -> dict[str, Any]:
        s = self._state
        now = time.time()
        code = str(s.WRITE_OTP or "")
        expires_at = float(s.WRITE_OTP_EXPIRES_AT or 0.0)
        # Do not mutate state while merely reading it.  An expired code is
        # projected as inactive; legacy Tkinter's timer may still call expire.
        active = bool(code and expires_at > now)
        return {
            "totp_secret": str(s.TOTP_SECRET),
            "provisioning_uri": self.provisioning_uri(),
            "pairing_code": code if active else "",
            "expires_at": expires_at if active else 0.0,
            "ttl_seconds": int(s.WRITE_OTP_TTL_SECONDS),
            "active": active,
            "qr_available": self.qr_available(),
        }

    def start_pairing(self) -> dict[str, Any]:
        self._state.reset_write_auth()
        return self.snapshot()

    def expire_pairing(self) -> dict[str, Any]:
        self._state.expire_write_otp()
        return self.snapshot()

    @staticmethod
    def qr_available() -> bool:
        try:
            import qrcode  # noqa: F401
            from PIL import Image  # noqa: F401
            return True
        except Exception:
            return False

    def qr_data_url(self) -> str | None:
        """Return the authenticator provisioning QR as a local PNG data URL.

        This mirrors the information encoded by the legacy Tkinter QR dialog.
        No external service or network request is involved.
        """
        if not self.qr_available():
            return None
        try:
            import qrcode
            qr = qrcode.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=7,
                border=4,
            )
            qr.add_data(self.provisioning_uri())
            qr.make(fit=True)
            image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
            return f"data:image/png;base64,{encoded}"
        except Exception as exc:
            raise PairingRuntimeError("unable to generate pairing QR") from exc


pairing_runtime_controller = PairingRuntimeController()

__all__ = ["PairingRuntimeController", "PairingRuntimeError", "pairing_runtime_controller"]
