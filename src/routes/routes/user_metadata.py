"""Trusted LAN routes for per-device favorites and annotations."""

import json

import src.state as state
from src.core.user_metadata import UserMetadataError, UserMetadataStore
from ..tunnel import _uses_public_access_policy


def _store() -> UserMetadataStore:
    return UserMetadataStore(state.USER_METADATA_PATH)


class UserMetadataRoutesMixin:
    def _user_metadata_guard(self) -> bool:
        if _uses_public_access_policy(self):
            self.send_error_json("Local network only", 403)
            return False
        if not self._has_device_credential():
            self.send_error_json("Trusted device required", 403)
            return False
        return True

    def _route_user_metadata_list(self):
        if self._user_metadata_guard():
            self.send_json({"favorites": _store().list(self._device_id())})

    def _route_user_metadata_upsert(self):
        if not self._user_metadata_guard():
            return
        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            item = _store().upsert(
                self._device_id(), str(payload.get("root_slot", "")),
                str(payload.get("path", "")),
                str(payload.get("annotation", "")),
            )
            self.send_json({"favorite": item}, 201)
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            self.send_error_json("Invalid favorite request", 400)
        except UserMetadataError as error:
            self.send_error_json(str(error), 400)

    def _route_user_metadata_delete(self, params):
        if not self._user_metadata_guard():
            return
        try:
            removed = _store().remove(
                self._device_id(),
                str(params.get("root_slot", [""])[0]),
                str(params.get("path", [""])[0]),
            )
            self.send_json({"removed": removed})
        except (IndexError, UserMetadataError) as error:
            self.send_error_json(str(error), 400)
