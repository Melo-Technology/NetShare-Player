"""Adapter over the existing WebSessionStore."""

from __future__ import annotations


class WebSessionAdapter:
    def __init__(self, store=None):
        if store is None:
            import src.state as state
            store = state.WEB_SESSION_STORE
        self.store = store

    def list(self):
        return tuple(self.store.list())

    def revoke(self, session_id: str) -> bool:
        return bool(self.store.revoke(session_id))

    def revoke_all(self) -> int:
        return int(self.store.revoke_all())
