"""Global Manage Folders API backed by the server configuration."""

import json

from src.core.folder_visibility import folder_children, folder_tree, set_folder_visibility


class FolderVisibilityRoutesMixin:
    def _route_folder_tree(self, params):
        requested = params.get("path", [""])[0]
        try:
            if requested:
                return self.send_json({"items": folder_children(requested)})
            self.send_json(folder_tree())
        except FileNotFoundError:
            self.send_error_json("Folder not found", 404)

    def _route_folder_hide(self):
        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            return self._set_folder_visibility(str(payload.get("path", "")), True)
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            self.send_error_json("Invalid folder visibility request", 400)

    def _route_folder_show(self, params):
        return self._set_folder_visibility(params.get("path", [""])[0], False)

    def _set_folder_visibility(self, requested: str, hidden: bool):
        try:
            self.send_json(set_folder_visibility(requested, hidden))
        except FileNotFoundError:
            self.send_error_json("Folder not found", 404)
        except ValueError as error:
            self.send_error_json(str(error), 400)
