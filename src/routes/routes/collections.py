"""API v2 smart-collection routes."""

import json
import threading
from pathlib import Path

import src.state as state
from src.core.file_index import _file_index
from src.core.hidden_folders import HIDDEN_MARKER_FILENAME, is_inside_hidden_folder
from src.core.smart_collections import CollectionError, SmartCollectionStore
from src.core import unlock_codes
from src.core.shared_paths import public_shared_path, resolve_shared_path


_stores = {}
_stores_lock = threading.Lock()


def _store():
    path = state._CONFIG_DIR / "smart_collections.json"
    key = str(path.resolve())
    with _stores_lock:
        return _stores.setdefault(key, SmartCollectionStore(_file_index, path))


class CollectionRoutesMixin:
    def _route_collections_list(self):
        self.send_json({"items": _store().list()})

    def _route_collection_items(self, collection_id: str, params):
        try:
            offset = int(params.get("offset", ["0"])[0])
            limit = int(params.get("limit", ["50"])[0])
            result = _store().items(
                    collection_id,
                    offset,
                    limit,
                    access_filter=self._collection_item_accessible,
                )
            for item in result.get("items", []):
                item["path"] = public_shared_path(
                    item.get("root_slot", "slot-1"), item["path"],
                )
            self.send_json(result)
        except (ValueError, CollectionError) as error:
            self.send_error_json(str(error), 404 if str(error) == "Collection not found" else 400)

    def _route_collection_create(self):
        payload = self._collection_body()
        if payload is None:
            return
        try:
            self.send_json(_store().create(payload.get("name", ""), payload.get("rules")), 201)
        except CollectionError as error:
            self.send_error_json(str(error), 400)

    def _route_collection_update(self, collection_id: str):
        payload = self._collection_body()
        if payload is None:
            return
        try:
            self.send_json(_store().update(collection_id, payload.get("name", ""), payload.get("rules")))
        except CollectionError as error:
            self.send_error_json(str(error), 404 if str(error) == "Collection not found" else 400)

    def _route_collection_delete(self, collection_id: str):
        try:
            _store().delete(collection_id)
            self.send_json({"ok": True})
        except CollectionError as error:
            self.send_error_json(str(error), 404)

    def _collection_body(self):
        body = self._read_body(32 * 1024)
        if body is None:
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.send_error_json("Invalid collection request", 400)
            return None

    def _collection_item_accessible(self, item):
        """Apply the same hidden-folder and protected-folder boundaries as browsing."""
        rel = str(item.get("path", ""))
        parts = Path(rel).parts
        if any(part.startswith(".") for part in parts) or any(
            part in (unlock_codes.MARKER_FILENAME, HIDDEN_MARKER_FILENAME)
            for part in parts
        ):
            return False
        resolved = resolve_shared_path(
            rel, default_slot=str(item.get("root_slot") or "slot-1"),
            visible=True,
        )
        if resolved is None or not resolved.path.is_file():
            return False
        if is_inside_hidden_folder(resolved.path, resolved.root):
            return False
        return not self._lock_status(rel)["locked"]
