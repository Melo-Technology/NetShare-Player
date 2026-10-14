"""Adapter for current local network addresses."""

from __future__ import annotations


class NetworkAdapter:
    def __init__(self, provider=None):
        if provider is None:
            from src.utils.network import get_local_ips
            provider = get_local_ips
        self._provider = provider

    def local_ips(self) -> tuple[str, ...]:
        return tuple(str(value) for value in self._provider())
