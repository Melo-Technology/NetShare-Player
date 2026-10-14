"""Bounded, persistent security telemetry and defensive IP blocking.

This component is intentionally independent from the HTTP handler.  Route/auth
code reports small facts (request, failed authentication, unknown route) while
this class owns thresholds, persistence, rotation and block decisions.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Callable

from src.core.data_vault import secure_unlink
from src.core.vault_storage import decode_jsonl_record, encode_jsonl_record, read_json, write_json


DEFAULT_SECURITY_CONFIG = {
    "enabled": True,
    "notify": False,
    "block_mode": "temporary",  # monitor | temporary | permanent
    "auth_failures": 8,
    "auth_window_seconds": 300,
    "block_seconds": 900,
    "burst_requests": 240,
    "burst_window_seconds": 60,
    "route_misses": 20,
    "route_window_seconds": 60,
}

_CONFIG_BOUNDS = {
    "auth_failures": (2, 100),
    "auth_window_seconds": (10, 86400),
    "block_seconds": (30, 604800),
    "burst_requests": (30, 10000),
    "burst_window_seconds": (5, 3600),
    "route_misses": (3, 1000),
    "route_window_seconds": (5, 3600),
}


def normalize_security_config(raw: dict[str, Any] | None) -> dict[str, Any]:
    value = dict(DEFAULT_SECURITY_CONFIG)
    if isinstance(raw, dict):
        value.update(raw)
    value["enabled"] = bool(value.get("enabled", True))
    value["notify"] = bool(value.get("notify", False))
    mode = str(value.get("block_mode") or "temporary").strip().lower()
    value["block_mode"] = mode if mode in {"monitor", "temporary", "permanent"} else "temporary"
    for key, (minimum, maximum) in _CONFIG_BOUNDS.items():
        try:
            parsed = int(value.get(key, DEFAULT_SECURITY_CONFIG[key]))
        except (TypeError, ValueError):
            parsed = int(DEFAULT_SECURITY_CONFIG[key])
        value[key] = max(minimum, min(maximum, parsed))
    return value


@dataclass(frozen=True)
class SecurityDecision:
    allowed: bool
    retry_after: int = 0
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": bool(self.allowed),
            "retry_after": max(0, int(self.retry_after)),
            "reason": str(self.reason),
        }


class SecurityMonitor:
    """Thread-safe monitor with bounded memory and rotating JSONL persistence."""

    def __init__(
        self,
        *,
        config_dir: Path,
        config: dict[str, Any] | None = None,
        clock: Callable[[], float] = time.time,
        notifier: Callable[[str, str], Any] | None = None,
        max_memory_events: int = 500,
        max_tracked_ips: int = 4096,
        log_max_bytes: int = 2 * 1024 * 1024,
        log_backups: int = 5,
    ) -> None:
        self._lock = threading.RLock()
        self._clock = clock
        self._notifier = notifier
        self._config = normalize_security_config(config)
        self._max_tracked_ips = max(64, int(max_tracked_ips))
        self._log_max_bytes = max(64 * 1024, int(log_max_bytes))
        self._log_backups = max(1, min(20, int(log_backups)))
        self._events: deque[dict[str, Any]] = deque(maxlen=max(50, int(max_memory_events)))
        self._requests: OrderedDict[str, deque[float]] = OrderedDict()
        self._auth: OrderedDict[str, deque[float]] = OrderedDict()
        self._misses: OrderedDict[str, deque[float]] = OrderedDict()
        self._alert_cooldown: dict[tuple[str, str], float] = {}
        self._notify_cooldown: dict[str, float] = {}
        self._blocks: dict[str, dict[str, Any]] = {}
        self._config_dir = Path(config_dir)
        self._log_path = self._config_dir / "security_events.jsonl"
        self._blocks_path = self._config_dir / "security_blocks.json"
        self._load_blocks()
        self._load_recent_events()

    def configure(self, config: dict[str, Any]) -> dict[str, Any]:
        normalized = normalize_security_config(config)
        with self._lock:
            self._config = normalized
            if not normalized["enabled"]:
                self._requests.clear()
                self._auth.clear()
                self._misses.clear()
        return self.snapshot(limit=200)

    def inspect_request(self, *, ip: str, method: str, path: str) -> SecurityDecision:
        clean_ip = self._clean_ip(ip)
        now = self._clock()
        with self._lock:
            self._cleanup_expired_blocks_locked(now)
            config = dict(self._config)
            # Disabling Security Monitoring must also suspend enforcement.  We
            # intentionally retain persisted blocks so re-enabling protection
            # restores the administrator's previous decisions, but a disabled
            # monitor never surprises the operator by continuing to reject IPs.
            if not config["enabled"]:
                return SecurityDecision(True)
            block = self._blocks.get(clean_ip)
            if block is not None:
                expiry = float(block.get("expires_at") or 0.0)
                retry = 0 if bool(block.get("permanent")) else max(1, int(expiry - now) + 1)
                return SecurityDecision(False, retry, str(block.get("reason") or "blocked"))
            if str(method).upper() == "OPTIONS":
                return SecurityDecision(True)
            count = self._append_window_locked(
                self._requests,
                clean_ip,
                now,
                int(config["burst_window_seconds"]),
            )
            if count <= int(config["burst_requests"]):
                return SecurityDecision(True)
            if not self._alert_due_locked("request_burst", clean_ip, now, int(config["burst_window_seconds"])):
                return SecurityDecision(True)
            self._record_event_locked(
                ip=clean_ip,
                event_type="request_burst",
                severity="warning",
                method=method,
                path=path,
                action="detected",
                detail=f"{count} requests/{config['burst_window_seconds']}s",
                now=now,
            )
            blocked = self._maybe_block_locked(clean_ip, "request_burst", now)
            if blocked:
                block = self._blocks.get(clean_ip, {})
                expiry = float(block.get("expires_at") or 0.0)
                retry = 0 if bool(block.get("permanent")) else max(1, int(expiry - now) + 1)
                return SecurityDecision(False, retry, "request_burst")
            return SecurityDecision(True)

    def record_auth_failure(self, *, ip: str, kind: str, path: str = "") -> dict[str, Any]:
        clean_ip = self._clean_ip(ip)
        clean_kind = self._clip(kind, 64) or "password"
        now = self._clock()
        with self._lock:
            config = dict(self._config)
            if not config["enabled"]:
                return {"blocked": False}
            count = self._append_window_locked(
                self._auth,
                clean_ip,
                now,
                int(config["auth_window_seconds"]),
            )
            self._record_event_locked(
                ip=clean_ip,
                event_type="auth_failure",
                severity="warning",
                path=path,
                action="observed",
                detail=f"{clean_kind} ({count}/{config['auth_failures']})",
                now=now,
            )
            blocked = False
            if count >= int(config["auth_failures"]):
                if self._alert_due_locked("brute_force", clean_ip, now, int(config["auth_window_seconds"])):
                    self._record_event_locked(
                        ip=clean_ip,
                        event_type="brute_force",
                        severity="danger",
                        path=path,
                        action="detected",
                        detail=f"{count} failed authentications/{config['auth_window_seconds']}s",
                        now=now,
                    )
                    blocked = self._maybe_block_locked(clean_ip, "brute_force", now)
            return {"blocked": bool(blocked), "failures": int(count)}

    def record_auth_success(self, *, ip: str) -> None:
        clean_ip = self._clean_ip(ip)
        with self._lock:
            self._auth.pop(clean_ip, None)

    def record_not_found(self, *, ip: str, method: str, path: str) -> dict[str, Any]:
        clean_ip = self._clean_ip(ip)
        now = self._clock()
        with self._lock:
            config = dict(self._config)
            if not config["enabled"]:
                return {"blocked": False}
            count = self._append_window_locked(
                self._misses,
                clean_ip,
                now,
                int(config["route_window_seconds"]),
            )
            # Persist the individual misses only up to the configured scan
            # threshold.  Once a source is clearly scanning, the summarized
            # route_scan event below is enough; this prevents monitor-only mode
            # from turning a hostile 404 flood into unbounded synchronous disk
            # writes (the rotating file is bounded either way).
            if count <= int(config["route_misses"]):
                self._record_event_locked(
                    ip=clean_ip,
                    event_type="route_not_found",
                    severity="info",
                    method=method,
                    path=path,
                    action="observed",
                    detail=f"unknown route ({count}/{config['route_misses']})",
                    now=now,
                )
            blocked = False
            if count >= int(config["route_misses"]):
                if self._alert_due_locked("route_scan", clean_ip, now, int(config["route_window_seconds"])):
                    self._record_event_locked(
                        ip=clean_ip,
                        event_type="route_scan",
                        severity="danger",
                        method=method,
                        path=path,
                        action="detected",
                        detail=f"{count} unknown routes/{config['route_window_seconds']}s",
                        now=now,
                    )
                    blocked = self._maybe_block_locked(clean_ip, "route_scan", now)
            return {"blocked": bool(blocked), "misses": int(count)}

    def snapshot(self, *, limit: int = 200) -> dict[str, Any]:
        now = self._clock()
        with self._lock:
            self._cleanup_expired_blocks_locked(now)
            events = list(self._events)[-max(1, min(500, int(limit))):]
            events.reverse()
            blocks = []
            for ip, record in sorted(self._blocks.items()):
                item = dict(record)
                item["ip"] = ip
                if not item.get("permanent"):
                    item["remaining_seconds"] = max(0, int(float(item.get("expires_at") or 0.0) - now))
                else:
                    item["remaining_seconds"] = None
                blocks.append(item)
            return {
                "config": dict(self._config),
                "events": [dict(event) for event in events],
                "blocked_ips": blocks,
                "event_count_in_memory": len(self._events),
                "log_path": str(self._log_path),
                "log_rotation": {
                    "max_bytes": int(self._log_max_bytes),
                    "backups": int(self._log_backups),
                },
            }

    def clear_history(self) -> None:
        with self._lock:
            self._events.clear()
            self._requests.clear()
            self._auth.clear()
            self._misses.clear()
            self._alert_cooldown.clear()
            for index in range(self._log_backups, 0, -1):
                path = self._log_path if index == 1 else Path(f"{self._log_path}.{index - 1}")
                target = Path(f"{self._log_path}.{index}")
                try:
                    secure_unlink(target)
                except OSError:
                    pass
                if index == 1:
                    try:
                        secure_unlink(path)
                    except OSError:
                        pass
            try:
                secure_unlink(self._log_path)
            except OSError:
                pass

    def unblock(self, ip: str) -> bool:
        clean_ip = self._clean_ip(ip)
        with self._lock:
            existed = self._blocks.pop(clean_ip, None) is not None
            if existed:
                self._persist_blocks_locked()
                self._record_event_locked(
                    ip=clean_ip,
                    event_type="ip_unblocked",
                    severity="info",
                    action="unblocked",
                    detail="manual unblock",
                    now=self._clock(),
                )
            return existed

    def _append_window_locked(
        self,
        store: OrderedDict[str, deque[float]],
        key: str,
        now: float,
        window: int,
    ) -> int:
        if key not in store:
            while len(store) >= self._max_tracked_ips:
                store.popitem(last=False)
            store[key] = deque()
        events = store.pop(key)
        store[key] = events
        cutoff = now - window
        while events and events[0] <= cutoff:
            events.popleft()
        events.append(now)
        return len(events)

    def _alert_due_locked(self, event_type: str, ip: str, now: float, window: int) -> bool:
        key = (event_type, ip)
        previous = float(self._alert_cooldown.get(key, 0.0))
        if previous and now - previous < max(5.0, float(window) / 2.0):
            return False
        self._alert_cooldown[key] = now
        return True

    def _maybe_block_locked(self, ip: str, reason: str, now: float) -> bool:
        mode = str(self._config.get("block_mode") or "temporary")
        if mode == "monitor" or self._is_protected_source(ip):
            action = "monitor_only" if mode == "monitor" else "protected_source"
            self._record_event_locked(
                ip=ip,
                event_type="block_skipped",
                severity="warning",
                action=action,
                detail=reason,
                now=now,
            )
            self._notify_locked(ip, reason, action)
            return False
        permanent = mode == "permanent"
        expires_at = 0.0 if permanent else now + int(self._config["block_seconds"])
        self._blocks[ip] = {
            "created_at": now,
            "expires_at": expires_at,
            "permanent": permanent,
            "reason": str(reason),
        }
        self._persist_blocks_locked()
        action = "blocked_permanently" if permanent else "blocked_temporarily"
        self._record_event_locked(
            ip=ip,
            event_type="ip_blocked",
            severity="danger",
            action=action,
            detail=reason,
            now=now,
        )
        self._notify_locked(ip, reason, action)
        return True

    def _notify_locked(self, ip: str, reason: str, action: str) -> None:
        if not self._config.get("notify") or self._notifier is None:
            return
        now = self._clock()
        if now - float(self._notify_cooldown.get(ip, 0.0)) < 30.0:
            return
        self._notify_cooldown[ip] = now
        try:
            self._notifier(
                "NetShare security alert",
                f"{ip}: {reason.replace('_', ' ')} — {action.replace('_', ' ')}",
            )
        except Exception:
            pass

    def _record_event_locked(
        self,
        *,
        ip: str,
        event_type: str,
        severity: str,
        action: str,
        detail: str,
        now: float,
        method: str = "",
        path: str = "",
    ) -> None:
        event = {
            "id": f"{int(now * 1000):x}-{secrets.token_hex(4)}",
            "timestamp": float(now),
            "ip": self._clip(ip, 96),
            "type": self._clip(event_type, 64),
            "severity": self._clip(severity, 16),
            "method": self._clip(str(method).upper(), 12),
            "path": self._clip(path, 256),
            "action": self._clip(action, 64),
            "detail": self._clip(detail, 256),
        }
        self._events.append(event)
        self._append_log_locked(event)

    def _append_log_locked(self, event: dict[str, Any]) -> None:
        try:
            self._config_dir.mkdir(parents=True, exist_ok=True)
            if self._log_path.exists() and self._log_path.stat().st_size >= self._log_max_bytes:
                self._rotate_logs_locked()
            line = encode_jsonl_record(event, purpose="security-events") + "\n"
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            # Monitoring must never make the server unavailable due to a
            # read-only profile or transient filesystem problem.
            pass

    def _rotate_logs_locked(self) -> None:
        try:
            oldest = Path(f"{self._log_path}.{self._log_backups}")
            oldest.unlink(missing_ok=True)
        except OSError:
            pass
        for index in range(self._log_backups - 1, 0, -1):
            source = Path(f"{self._log_path}.{index}")
            target = Path(f"{self._log_path}.{index + 1}")
            try:
                if source.exists():
                    os.replace(source, target)
            except OSError:
                pass
        try:
            if self._log_path.exists():
                os.replace(self._log_path, Path(f"{self._log_path}.1"))
        except OSError:
            pass

    def _load_recent_events(self) -> None:
        try:
            if not self._log_path.exists():
                return
            lines = self._log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines[-self._events.maxlen:]:
                value = decode_jsonl_record(line, purpose="security-events")
                if isinstance(value, dict):
                    self._events.append(value)
        except OSError:
            pass

    def _persist_blocks_locked(self) -> None:
        data = {"version": 1, "blocks": self._blocks}
        try:
            write_json(self._blocks_path, data, purpose="security-blocks", indent=2)
        except OSError:
            pass

    def _load_blocks(self) -> None:
        raw = read_json(self._blocks_path, purpose="security-blocks", default={})
        blocks = raw.get("blocks") if isinstance(raw, dict) else None
        if not isinstance(blocks, dict):
            return
        now = self._clock()
        with self._lock:
            for ip, record in blocks.items():
                if not isinstance(record, dict):
                    continue
                clean_ip = self._clean_ip(ip)
                permanent = bool(record.get("permanent"))
                try:
                    expiry = float(record.get("expires_at") or 0.0)
                except (TypeError, ValueError):
                    continue
                if not permanent and expiry <= now:
                    continue
                self._blocks[clean_ip] = {
                    "created_at": float(record.get("created_at") or now),
                    "expires_at": expiry,
                    "permanent": permanent,
                    "reason": self._clip(record.get("reason") or "blocked", 64),
                }
            if len(self._blocks) != len(blocks):
                self._persist_blocks_locked()

    def _cleanup_expired_blocks_locked(self, now: float) -> None:
        expired = [
            ip for ip, record in self._blocks.items()
            if not bool(record.get("permanent")) and float(record.get("expires_at") or 0.0) <= now
        ]
        if not expired:
            return
        for ip in expired:
            self._blocks.pop(ip, None)
        self._persist_blocks_locked()

    @staticmethod
    def _is_protected_source(ip: str) -> bool:
        try:
            return ipaddress.ip_address(str(ip)).is_loopback
        except ValueError:
            return str(ip).lower() in {"localhost", "<unknown>"}

    @staticmethod
    def _clean_ip(value: str) -> str:
        clean = str(value or "<unknown>").strip()
        return clean[:96] or "<unknown>"

    @staticmethod
    def _clip(value: Any, limit: int) -> str:
        return str(value or "").replace("\r", " ").replace("\n", " ")[: max(1, int(limit))]


__all__ = [
    "DEFAULT_SECURITY_CONFIG",
    "normalize_security_config",
    "SecurityDecision",
    "SecurityMonitor",
]
