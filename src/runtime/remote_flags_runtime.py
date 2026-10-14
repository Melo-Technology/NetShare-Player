"""Process-local cache of the Remote Config feature flags used by desktop UIs.

Tkinter historically kept these values in ``App._remote_flags`` with a tri-state
contract: ``None`` means that the remote value has not been fetched yet, so the
corresponding control remains visible.  The WebView server path needs the same
source-of-truth without persisting anything or changing ``src.state`` schemas.
"""
from __future__ import annotations

import threading
from typing import Mapping


class RemoteFlagsRuntimeController:
    """Thread-safe mirror of the legacy Tkinter remote flag cache."""

    _DEFAULTS = {
        "upload": None,
        "document_edit": None,
        # ``None`` means Remote Config has not supplied a value in this
        # process yet.  The local Master/Slave role remains an explicit opt-in,
        # while an actual remote ``False`` still wins and disables clustering.
        "cluster": None,
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._flags: dict[str, bool | None] = dict(self._DEFAULTS)

    def reset_defaults(self) -> dict[str, bool | None]:
        with self._lock:
            self._flags = dict(self._DEFAULTS)
            return dict(self._flags)

    def snapshot(self) -> dict[str, bool | None]:
        with self._lock:
            return dict(self._flags)

    def update(self, values: Mapping[str, object]) -> dict[str, bool | None]:
        with self._lock:
            for key in self._DEFAULTS:
                if key not in values:
                    continue
                value = values[key]
                if value is None:
                    self._flags[key] = None
                else:
                    self._flags[key] = bool(value)
            return dict(self._flags)


remote_flags_runtime_controller = RemoteFlagsRuntimeController()

__all__ = ["RemoteFlagsRuntimeController", "remote_flags_runtime_controller"]
