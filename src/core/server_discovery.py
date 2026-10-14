"""Continuous, privacy-minimised DNS-SD advertisement for Player discovery."""

from __future__ import annotations

import ipaddress
import secrets
import threading
import time

from src.constants import VERSION
from src.deps import HAS_ZEROCONF

SERVICE_TYPE = "_netshare._tcp.local."
PROTOCOL_VERSION = "1"
SERVICE_TTL_SECONDS = 30
MIN_RESTART_INTERVAL_SECONDS = 5.0
MAX_TXT_VALUE_BYTES = 64


class ServerDiscoveryUnavailable(RuntimeError):
    pass


def _zeroconf_types():
    if not HAS_ZEROCONF:
        raise ServerDiscoveryUnavailable("python-zeroconf is not installed")
    from zeroconf import ServiceInfo, Zeroconf
    return ServiceInfo, Zeroconf


def _local_addresses(addresses: list[str]) -> tuple[str, ...]:
    accepted = []
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            continue
        if not address.is_loopback and (address.is_private or address.is_link_local):
            accepted.append(str(address))
    return tuple(dict.fromkeys(accepted))


class ServerDiscoveryAdvertiser:
    """Own one bounded advertisement for the lifetime of the HTTP server.

    python-zeroconf applies DNS known-answer suppression, duplicate-question
    suppression and response aggregation. The app additionally prevents rapid
    unregister/register loops, limits the address family to explicit LAN
    addresses, and keeps both the response and amplification factor bounded by
    publishing bounded, non-identifying TXT values only.
    """

    def __init__(self, *, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.RLock()
        self._zeroconf = None
        self._info = None
        self._last_start = float("-inf")

    @property
    def active(self) -> bool:
        with self._lock:
            return self._zeroconf is not None

    def start(
        self,
        *,
        addresses: list[str],
        port: int,
        password_protected: bool,
        tls_enabled: bool = False,
        capabilities: tuple[str, ...] = (),
    ) -> None:
        with self._lock:
            if self._zeroconf is not None:
                raise RuntimeError("server discovery is already active")
            now = self._clock()
            if now - self._last_start < MIN_RESTART_INTERVAL_SECONDS:
                raise RuntimeError("server discovery restart is rate limited")
            local_addresses = _local_addresses(addresses)
            if not local_addresses or not 1 <= int(port) <= 65535:
                raise ValueError("invalid server discovery endpoint")
            safe_capabilities = ",".join(
                sorted({
                    value
                    for value in capabilities
                    if value.isascii()
                    and all(character.isalnum() or character == "_" for character in value)
                })
            )[:MAX_TXT_VALUE_BYTES]
            properties = {
                "v": VERSION[:MAX_TXT_VALUE_BYTES],
                "api": PROTOCOL_VERSION,
                "caps": safe_capabilities,
                "pw": "1" if password_protected else "0",
                "tls": "1" if tls_enabled else "0",
            }
            ServiceInfo, Zeroconf = _zeroconf_types()
            instance = secrets.token_hex(8)
            zeroconf = Zeroconf()
            info = ServiceInfo(
                SERVICE_TYPE,
                f"NetShare-{instance}.{SERVICE_TYPE}",
                parsed_addresses=list(local_addresses),
                port=int(port),
                properties=properties,
            )
            try:
                zeroconf.register_service(
                    info,
                    ttl=SERVICE_TTL_SECONDS,
                    allow_name_change=False,
                )
            except Exception:
                zeroconf.close()
                raise
            self._zeroconf = zeroconf
            self._info = info
            self._last_start = now

    def stop(self) -> None:
        with self._lock:
            zeroconf, info = self._zeroconf, self._info
            self._zeroconf = None
            self._info = None
        if zeroconf is not None:
            try:
                if info is not None:
                    zeroconf.unregister_service(info)
            finally:
                zeroconf.close()
