"""LAN-only API v2 route for offline pin manifests."""

import json

from src.core.file_index import _file_index
from src.core.offline_manifests import OfflineManifestError, build_manifest
from ..tunnel import _uses_public_access_policy


class OfflineRoutesMixin:
    def _route_offline_manifest(self):
        if _uses_public_access_policy(self):
            return self.send_error_json("LAN only", 403)
        body = self._read_body(32 * 1024)
        if body is None:
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
            manifest = build_manifest(_file_index, payload.get("paths"))
            self.send_json(manifest)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OfflineManifestError) as error:
            self.send_error_json(str(error) or "Invalid manifest request", 400)
