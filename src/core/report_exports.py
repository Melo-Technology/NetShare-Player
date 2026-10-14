"""Administrative XLSX exports for transfer history and server diagnostics."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import src.state as state
from src.constants import VERSION
from src.core.inbox import InboxService
from src.core.server_tls import is_transport_tls_active
from src.core.xlsx_export import write_xlsx

_HTTP_LOG = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+->\s+(\d+)\s+\[([^\]]*)\]")
_SENSITIVE_QUERY_KEYS = {"token", "access_token", "refresh_token", "key", "api_key", "password", "secret", "code", "credential", "auth", "authorization", "recovery_key", "recovery_phrase", "dek", "kek", "vault_key", "wrapped_dek"}


def _redact_request_target(value: str) -> str:
    """Keep route diagnostics useful without exporting credentials in URLs."""
    raw = str(value or "")
    try:
        parts = urlsplit(raw)
        if not parts.query:
            return raw
        sanitized = []
        for key, item in parse_qsl(parts.query, keep_blank_values=True):
            sanitized.append((key, "[REDACTED]" if key.casefold() in _SENSITIVE_QUERY_KEYS else item))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(sanitized), parts.fragment))
    except Exception:
        return raw.split("?", 1)[0] + ("?[REDACTED]" if "?" in raw else "")


def _stamp(value) -> str:
    try:
        raw = float(value or 0)
        return datetime.fromtimestamp(raw).isoformat(timespec="seconds") if raw > 0 else ""
    except (TypeError, ValueError, OSError):
        return ""


def _transfer_rows() -> list[list]:
    service = InboxService(state.INBOX_DIR, state.INBOX_HISTORY_PATH)
    rows = [[
        "Timestamp", "File", "Size bytes", "Source", "Status",
        "Destination type", "Destination slot", "Destination path", "Inbox path",
    ]]
    for item in service.history():
        rows.append([
            _stamp(item.get("timestamp")), item.get("name") or Path(str(item.get("path") or "")).name,
            int(item.get("size") or 0), item.get("source") or "", item.get("status") or "",
            item.get("destination_type") or "", item.get("destination_slot") or "",
            item.get("destination_path") or "", item.get("inbox_path") or "",
        ])
    return rows


def export_transfer_report(target_path: str | Path) -> Path:
    rows = _transfer_rows()
    summary = [
        ["NetShare transfer report", ""],
        ["Generated", datetime.now().isoformat(timespec="seconds")],
        ["Recorded transfers", max(0, len(rows) - 1)],
        ["History maximum", 1000],
    ]
    return write_xlsx(target_path, [("Summary", summary), ("Transfers", rows)])


def export_server_report(target_path: str | Path) -> Path:
    from src.runtime.activity_runtime import activity_runtime
    from src.runtime.security_monitor_runtime import security_monitor_runtime

    live = activity_runtime.snapshot()
    security = security_monitor_runtime.snapshot(limit=500)
    transfers = _transfer_rows()

    traffic_rows = [["Timestamp", "Method", "Path", "Status", "Client", "Kind", "Raw message"]]
    traffic_counter: Counter[tuple[str, str, str]] = Counter()
    for entry in live.get("logs", []):
        message = str(entry.get("message") or "")
        match = _HTTP_LOG.match(message)
        if not match:
            continue
        method, path, status, client = match.groups()
        safe_path = _redact_request_target(path)
        safe_message = f"{method} {safe_path} -> {status} [{client}]"
        traffic_rows.append([
            _stamp(entry.get("time")), method, safe_path, int(status), client,
            str(entry.get("kind") or "info"), safe_message,
        ])
        traffic_counter[(method, safe_path, status)] += 1
    traffic_summary = [["Method", "Path", "Status", "Requests"]]
    for (method, path, status), count in sorted(traffic_counter.items(), key=lambda item: (-item[1], item[0])):
        traffic_summary.append([method, path, int(status), count])

    security_events = [["Timestamp", "IP", "Type", "Severity", "Action", "Detail"]]
    for event in security.get("events", []):
        security_events.append([
            _stamp(event.get("timestamp") or event.get("time")), event.get("ip") or "",
            event.get("event_type") or event.get("type") or "", event.get("severity") or "",
            event.get("action") or "", event.get("detail") or "",
        ])
    security_blocks = [["IP", "Reason", "Permanent", "Created", "Expires", "Remaining seconds"]]
    for item in security.get("blocked_ips", []):
        security_blocks.append([
            item.get("ip") or "", item.get("reason") or item.get("detail") or "",
            bool(item.get("permanent")), _stamp(item.get("created_at")), _stamp(item.get("expires_at")),
            item.get("remaining_seconds"),
        ])

    trusted_rows = [["Device ID", "Paired at", "Credential present"]]
    for device_id, raw in sorted(state.TRUSTED_DEVICES.items()):
        record = raw if isinstance(raw, dict) else {"paired_at": raw}
        trusted_rows.append([
            str(device_id), _stamp(record.get("paired_at") or record.get("registered_at") or raw),
            bool(record.get("credential_hash") or record.get("credential")) if isinstance(record, dict) else False,
        ])

    activity_rows = [["Timestamp", "Stream", "Status/Kind", "Path/Message", "Client", "Progress %"]]
    for item in live.get("write_activity", []):
        activity_rows.append([_stamp(item.get("time")), "write", item.get("action") or "", item.get("path") or "", item.get("client") or "", ""])
    for item in live.get("transfers", []):
        activity_rows.append([_stamp(item.get("time")), "transfer", item.get("status") or "", item.get("filename") or item.get("path") or "", item.get("client") or "", round(float(item.get("progress") or 0) * 100, 2)])

    config = security.get("config") or {}
    summary = [
        ["NetShare Server report", ""],
        ["Generated", datetime.now().isoformat(timespec="seconds")],
        ["Version", VERSION],
        ["Server ID", str(state.SERVER_ID)],
        ["TLS local transport", is_transport_tls_active()],
        ["Cluster role", str(getattr(state, "CLUSTER_ROLE", "standalone"))],
        ["Shared roots", len(getattr(state, "SHARED_ROOTS", ()))],
        ["Trusted devices", len(getattr(state, "TRUSTED_DEVICES", {}))],
        ["Recorded transfers", max(0, len(transfers) - 1)],
        ["Buffered HTTP traffic records", max(0, len(traffic_rows) - 1)],
        ["Buffered security events", len(security.get("events", []))],
        ["Blocked IPs", len(security.get("blocked_ips", []))],
        ["Security monitoring enabled", bool(config.get("enabled"))],
        ["Report note", "Secrets, passwords, access tokens and private keys are intentionally excluded."],
        ["Generated epoch", time.time()],
    ]

    return write_xlsx(target_path, [
        ("Summary", summary),
        ("Transfers", transfers),
        ("Traffic Summary", traffic_summary),
        ("Traffic", traffic_rows),
        ("Security Events", security_events),
        ("Security Blocks", security_blocks),
        ("Trusted Devices", trusted_rows),
        ("Live Activity", activity_rows),
    ])
