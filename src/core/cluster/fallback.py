"""Bounded standalone fallback for a linked Slave.

Master display metadata is accepted only from the encrypted SAS enrollment
envelope or from an authenticated mTLS heartbeat. Discovery and HTTP inputs
never call this service, preventing a LAN peer from replacing the reconnect
target shown to Players.
"""

from __future__ import annotations

import json
import ipaddress
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

FALLBACK_AFTER_SECONDS = 70.0


class SlaveFallbackState:
    def __init__(
        self, path: Path, *, timeout: float = FALLBACK_AFTER_SECONDS,
        clock=time.monotonic, on_change=lambda _enabled, _metadata: None,
    ):
        self.path = Path(path)
        self.timeout = float(timeout)
        self._clock = clock
        self._on_change = on_change
        self._lock = threading.RLock()
        self._last_heartbeat = self._clock()
        self._enabled = False
        self._linked = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._metadata = self._load()

    @property
    def metadata(self) -> dict:
        with self._lock:
            return dict(self._metadata)

    def arm_linked(self) -> None:
        with self._lock:
            self._linked = True
            self._last_heartbeat = self._clock()
            self._set_enabled_locked(False)

    def record_authenticated_master(self, name: str, url: str) -> None:
        """Record metadata proven by SAS or mTLS; never expose a LAN setter."""
        clean_name = str(name).strip()[:128]
        clean_url = self._validate_master_url(url)
        with self._lock:
            self._linked = True
            self._last_heartbeat = self._clock()
            if clean_name and clean_url:
                value = {"name": clean_name, "url": clean_url}
                if value != self._metadata:
                    self._metadata = value
                    self._save_locked()
            self._set_enabled_locked(False)

    def direct_http_enabled(self) -> bool:
        with self._lock:
            return self._refresh_locked()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._monitor, daemon=True,
                name="netshare-cluster-fallback",
            )
            self._thread.start()

    def clear_relation(self) -> None:
        with self._lock:
            self._linked = False
            self._set_enabled_locked(False)
            self._metadata = {}
            self.path.unlink(missing_ok=True)

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)

    def _monitor(self) -> None:
        while not self._stop.wait(1.0):
            self.direct_http_enabled()

    def _refresh_locked(self) -> bool:
        enabled = (
            self._linked
            and self._clock() - self._last_heartbeat >= self.timeout
        )
        self._set_enabled_locked(enabled)
        return self._enabled

    def _set_enabled_locked(self, enabled: bool) -> None:
        enabled = bool(enabled)
        if enabled == self._enabled:
            return
        self._enabled = enabled
        self._on_change(enabled, dict(self._metadata))

    def _load(self) -> dict:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            name = str(value.get("name", "")).strip()[:128]
            url = self._validate_master_url(value.get("url", ""))
            return {"name": name, "url": url} if name and url else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(self._metadata, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)

    @staticmethod
    def _validate_master_url(value: str) -> str:
        parsed = urlparse(str(value).strip())
        if parsed.scheme != "http" or not parsed.hostname or parsed.path not in ("", "/"):
            return ""
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return ""
        try:
            port = parsed.port
        except ValueError:
            return ""
        if port is None or not 1 <= port <= 65535:
            return ""
        host = parsed.hostname.lower()
        try:
            address = ipaddress.ip_address(host)
            if not (address.is_private or address.is_link_local or address.is_loopback):
                return ""
        except ValueError:
            if not host.endswith(".local"):
                return ""
        return f"http://{host}:{port}"
