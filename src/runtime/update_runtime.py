"""Conservative update discovery for NetShare Server.

The desktop app checks the project's GitHub Releases metadata over HTTPS and
never replaces its own executable.  Installation remains an explicit user
choice via the release page / packaged installer for the current OS.  This
keeps EXE/AppImage/DMG updates compatible with platform signing/notarization.
"""
from __future__ import annotations

import json
import os
import platform
import re
from typing import Any, Callable
from urllib.request import Request, urlopen

from src.constants import VERSION

REPOSITORY = os.environ.get("NETSHARE_UPDATE_REPOSITORY", "Melo-Technology/NetShare-Player").strip() or "Melo-Technology/NetShare-Player"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
LATEST_RELEASE_PAGE = f"https://github.com/{REPOSITORY}/releases/latest"


def _version_tuple(value: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", str(value or "").lstrip("vV"))
    return tuple(int(part) for part in numbers[:4]) or (0,)


class UpdateRuntimeController:
    def __init__(self, *, opener: Callable[..., Any] | None = None) -> None:
        self._opener = opener or urlopen

    @staticmethod
    def base_snapshot() -> dict[str, Any]:
        return {
            "current_version": str(VERSION),
            "check_available": True,
            "status": "idle",
            "source": "github_releases",
            "release_url": LATEST_RELEASE_PAGE,
            "latest_version": None,
            "update_available": False,
            "asset_url": None,
            "asset_name": None,
            "published_at": None,
        }

    @staticmethod
    def _preferred_asset(assets: list[dict[str, Any]]) -> dict[str, Any] | None:
        system = platform.system().lower()
        suffixes = {
            "windows": (".exe",),
            "darwin": (".dmg",),
            "linux": (".appimage",),
        }.get(system, ())
        for suffix in suffixes:
            for asset in assets:
                name = str(asset.get("name") or "")
                if name.lower().endswith(suffix):
                    return asset
        return None

    def check(self, *, timeout: float = 5.0) -> dict[str, Any]:
        snapshot = self.base_snapshot()
        request = Request(
            LATEST_RELEASE_API,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"NetShare-Server/{VERSION}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self._opener(request, timeout=float(timeout)) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            snapshot.update({"status": "check_failed", "error_type": type(exc).__name__})
            return snapshot

        tag = str(payload.get("tag_name") or payload.get("name") or "").strip()
        if not tag:
            snapshot.update({"status": "check_failed", "error_type": "InvalidReleaseMetadata"})
            return snapshot
        current = _version_tuple(VERSION)
        latest = _version_tuple(tag)
        available = latest > current
        release_url = str(payload.get("html_url") or LATEST_RELEASE_PAGE)
        asset = self._preferred_asset(list(payload.get("assets") or []))
        snapshot.update(
            {
                "status": "update_available" if available else "up_to_date",
                "latest_version": tag.lstrip("vV"),
                "update_available": available,
                "release_url": release_url,
                "asset_url": str(asset.get("browser_download_url")) if asset and asset.get("browser_download_url") else None,
                "asset_name": str(asset.get("name")) if asset and asset.get("name") else None,
                "published_at": str(payload.get("published_at")) if payload.get("published_at") else None,
            }
        )
        return snapshot


update_runtime_controller = UpdateRuntimeController()

__all__ = [
    "UpdateRuntimeController",
    "update_runtime_controller",
    "LATEST_RELEASE_API",
    "LATEST_RELEASE_PAGE",
]
