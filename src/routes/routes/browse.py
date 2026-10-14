"""
Directory browsing: /list, /search, /media-analysis.
"""

from pathlib import Path
import hashlib

import src.state as state
from src.core import unlock_codes
from src.core.media_analysis import ANALYSIS_VERSION, is_audio
from src.core.derived_media import derived_media_service
from src.core.hidden_folders import (
    HIDDEN_MARKER_FILENAME,
    is_hidden_folder,
    is_inside_hidden_folder,
)
from src.core.content_policy import visible_shared_entry
from src.core.content_policy import is_config_hidden, profile_allows_path
from src.core.cloud import get_manager
from src.core.shared_paths import public_shared_path, resolve_shared_path
from src.utils.network import safe_path, file_info
from ..tunnel import _uses_public_access_policy


class BrowseRoutesMixin:

    def _route_list(self, params):
        rel    = params.get("path", ["/"])[0]
        paginated = "limit" in params or "offset" in params
        try:
            limit = min(int(params.get("limit", ["100"])[0]), 200)
            offset = int(params.get("offset", ["0"])[0])
            if limit < 1 or offset < 0:
                raise ValueError
        except (ValueError, IndexError):
            return self.send_error_json("Invalid pagination", 400)
        allowed_paths = self._guest_allowed_paths()
        cluster_path = self._parse_cluster_virtual_path(rel)
        if cluster_path:
            return self._route_cluster_virtual_list(*cluster_path)
        cloud_path = self._parse_cloud_virtual_path(rel)
        if cloud_path:
            return self._route_cloud_virtual_list(
                *cloud_path,
                offset=offset if paginated else None,
                limit=limit if paginated else None,
                refresh=bool(params.get("refresh", [""])[0]),
            )
        if _uses_public_access_policy(self) and self._public_role() == "community":
            if not state.COMMUNITY_BROWSE_ROOT:
                # The dedicated Inbox is private operational storage. Community
                # access must not inherit visibility merely because the legacy
                # folder used to live below slot-1.
                return self.send_json([])
        merged_root = rel in ("/", "")
        raw_resolved = None if merged_root else resolve_shared_path(rel)
        if not merged_root and raw_resolved is None:
            return self.send_error_json("Invalid path", 403)
        resolved = None if merged_root else resolve_shared_path(
            rel, visible=True, allowed_paths=allowed_paths,
        )
        if not merged_root and resolved is None:
            return self.send_error_json("Directory not found", 404)
        targets = (
            [(root.slot, root.path) for root in state.SHARED_ROOTS]
            if merged_root else [(resolved.slot, resolved.path)]
        )
        if any(not target.exists() for _, target in targets):
            return self.send_error_json("Directory not found", 404)
        if not merged_root and is_inside_hidden_folder(resolved.path, resolved.root):
            return self.send_error_json("Directory not found", 404)
        if any(not target.is_dir() for _, target in targets):
            return self.send_error_json("Not a directory", 400)
        lock = self._lock_status(rel)
        if lock["locked"]:
            return self.send_json({
                "error": "premium_locked",
                "folder_path": lock["folder_path"],
                "label": lock["label"],
                "price_note": lock["price_note"],
            }, 403)
        try:
            etag = '"' + hashlib.sha256(
                "\0".join(self._directory_etag(target) for _, target in targets).encode("utf-8")
            ).hexdigest() + '"'
            cluster_roots = []
            if rel in ("/", ""):
                cluster_roots = self._cluster_virtual_roots()
                cluster_signature = "\0".join(
                    sorted(
                        f"{item['cluster_node_id']}:{item['name']}"
                        for item in cluster_roots
                    )
                )
                cloud_signature = "\0".join(
                    sorted(
                        f"{item.get('provider_id', '')}:{item.get('account_id', '')}:{item.get('label', '')}"
                        for item in get_manager().connected_accounts()
                    )
                )
                etag = (
                    '"'
                    + hashlib.sha256(
                        f"{etag}\0cluster\0{cluster_signature}\0cloud\0{cloud_signature}".encode("utf-8")
                    ).hexdigest()
                    + '"'
                )
            if self.headers.get("If-None-Match", "").strip() == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Content-Length", "0")
                self._send_cors_headers()
                self.end_headers()
                return
            items = []
            local_items = []
            pagination_total = None
            can_page_local_entries = (
                paginated
                and len(targets) == 1
                and (
                    not merged_root
                    or (
                        not cluster_roots
                        and (
                            allowed_paths is not None
                            or not get_manager().connected_accounts()
                        )
                    )
                )
            )
            for root_slot, target in targets:
                physical_root = state.root_for_slot(root_slot)
                entries = sorted(
                    target.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()),
                )
                entries_are_visible = False
                if can_page_local_entries:
                    visible_entries = []
                    for entry in entries:
                        try:
                            if visible_shared_entry(
                                entry, root=physical_root, slot=root_slot,
                                allowed_paths=allowed_paths,
                            ):
                                visible_entries.append(entry)
                        except (PermissionError, OSError):
                            pass
                    pagination_total = len(visible_entries)
                    entries = visible_entries[offset:offset + limit]
                    entries_are_visible = True
                for entry in entries:
                    try:
                        if not entries_are_visible and not visible_shared_entry(
                            entry, root=physical_root, slot=root_slot,
                            allowed_paths=allowed_paths,
                        ):
                            continue
                        info = file_info(entry, physical_root, root_slot)
                        if entry.is_file() and is_audio(entry):
                            from src.core.file_index import _file_index
                            indexed_path = "/" + str(entry.relative_to(physical_root)).replace("\\", "/")
                            info["loudness_gain"] = _file_index.loudness_gain(indexed_path, root_slot)
                            info["bpm"] = _file_index.bpm(indexed_path, root_slot)
                        if entry.is_dir() and unlock_codes.is_premium_folder(info["path"]):
                            sub_lock = self._lock_status(info["path"])
                            info["premium"] = True
                            info["locked"] = sub_lock["locked"]
                            info["premium_label"] = sub_lock.get("label", "")
                            info["premium_price_note"] = sub_lock.get("price_note", "")
                        local_items.append(info)
                    except (PermissionError, OSError):
                        pass
            if merged_root and len(targets) > 1:
                name_counts = {}
                for info in local_items:
                    key = info["name"].casefold()
                    name_counts[key] = name_counts.get(key, 0) + 1
                for info in local_items:
                    if name_counts[info["name"].casefold()] > 1:
                        info["name_collision"] = True
                        source = state.root_for_slot(info["root_slot"])
                        info["source_name"] = source.name or str(source)
            items.extend(sorted(
                local_items,
                key=lambda item: (not item["is_dir"], item["name"].casefold(), item["root_slot"]),
            ))
            if merged_root and allowed_paths is None:
                items.extend(cluster_roots)
                for account in reversed(get_manager().connected_accounts()):
                    provider_id = account.get("provider_id", "")
                    account_id = account.get("account_id", "")
                    if provider_id and account_id:
                        items.insert(0, {
                            "name": account.get("label") or f"{provider_id} cloud",
                            "path": self._cloud_virtual_path(provider_id, account_id),
                            "is_dir": True,
                            "size": None,
                            "modified": "",
                            "cloud_provider": provider_id,
                        })
            if paginated:
                page = items if pagination_total is not None else items[offset:offset + limit]
                total = pagination_total if pagination_total is not None else len(items)
                return self.send_json({
                    "items": page,
                    "offset": offset,
                    "limit": limit,
                    "total": total,
                    "has_more": offset + len(page) < total,
                }, headers={"ETag": etag})
            self.send_json(items, headers={"ETag": etag})
        except PermissionError:
            self.send_error_json("Permission denied", 403)

    def _route_search(self, params):
        """Search the file index or invalidate and rebuild it on demand."""
        from src.core.file_index import _file_index
        if _uses_public_access_policy(self) and self._public_role() == "community":
            return self.send_error_json("Search is not available for community access", 403)
        if params.get("invalidate"):
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            _file_index.clear()
            for shared_root in state.SHARED_ROOTS:
                _file_index.invalidate_cache(shared_root.path)
            _file_index.build_all(state.SHARED_ROOTS)
            return self.send_json({"ok": True, "message": "cache invalidated, reindexing"})
        if params.get("ready"):
            return self.send_json({"ready": _file_index.ready, "total": _file_index.total})
        query = params.get("q", [""])[0]
        file_type = params.get("type", ["all"])[0]
        if not query.strip() and file_type.lower() == "all":
            return self.send_json({"items": [], "total": 0, "offset": 0, "has_more": False})
        try:
            limit  = min(int(params.get("limit",  ["50"])[0]), 200)
        except (ValueError, IndexError):
            limit = 50
        try:
            offset = max(int(params.get("offset", ["0"])[0]), 0)
        except (ValueError, IndexError):
            offset = 0
        result = _file_index.search(
            query, limit=limit, offset=offset, file_type=file_type,
            access_filter=lambda item: (
                not is_config_hidden(
                    item.get("root_slot", "slot-1"), item.get("path", ""),
                )
                and profile_allows_path(
                    item.get("root_slot", "slot-1"), item.get("path", ""),
                    self._guest_allowed_paths(),
                )
            ),
        )
        device_id = self._device_id()
        for item in result.get("items", []):
            item["path"] = public_shared_path(item.get("root_slot", "slot-1"), item["path"])
            lock = unlock_codes.lock_status_for_path(item["path"], device_id)
            if lock["locked"]:
                item["locked"] = True
                item["premium_label"] = lock.get("label", "")
            if is_audio(Path(item["name"])):
                item["loudness_gain"] = item.get("loudness_gain")
                item["bpm"] = item.get("bpm")
        self.send_json(result)

    def _route_media_analysis(self, params):
        """Return heavier analysis only when a client opens one audio file."""
        from src.core.file_index import _file_index
        rel = params.get("path", [""])[0]
        cluster_path = self._parse_cluster_virtual_path(rel)
        if cluster_path:
            return self._route_cluster_derived(*cluster_path, "MEDIA_ANALYSIS", {})
        resolved = resolve_shared_path(
            rel, visible=True, require_file=True,
            allowed_paths=self._guest_allowed_paths(),
        ) if rel else None
        target = resolved.path if resolved else None
        if target is None:
            return self.send_error_json("Audio file not found", 404)
        if not target.is_file() or not is_audio(target):
            return self.send_error_json("Audio file not found", 404)
        lock = self._lock_status(rel)
        if lock["locked"]:
            return self.send_error_json("Premium content locked", 403)
        return self._send_derived(derived_media_service.media_analysis(rel, target))
