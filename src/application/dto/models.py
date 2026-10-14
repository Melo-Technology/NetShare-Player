"""JSON-native data-transfer object contracts for Application Services.

DTOs are ``TypedDict`` declarations rather than runtime dataclass instances.
Constructing one therefore returns a plain ``dict`` and every service boundary
can be serialized directly with ``json.dumps(...)`` without a custom encoder,
``asdict()``, or ``to_dict()`` conversion.
"""

from __future__ import annotations

from typing import TypedDict


class SharedRootDTO(TypedDict):
    slot: str
    path: str
    name: str


class SettingsSnapshotDTO(TypedDict):
    theme: str
    language: str
    text_size: str
    show_advanced_settings: bool
    ffmpeg_path: str
    performance_preset: str
    index_workers: int | None
    analysis_workers: int | None
    gpu_encoder_preference: str
    log_buffer_lines: int
    cluster_role: str
    password_reminder_days: int
    local_password_configured: bool


class WorkerBudgetDTO(TypedDict):
    cpu_count_logical: int
    hard_total: int
    index_workers: int
    analysis_workers: int
    adjusted: str | None


class WebSessionDTO(TypedDict):
    id: str
    role: str
    created_at: float
    last_seen_at: float
    expires_at: float
    idle_expires_at: float
    browser_family: str
    os_family: str


class PublicSharingDTO(TypedDict):
    community_key_configured: bool
    admin_key_configured: bool
    community_browse_root: bool
    community_download: bool
    community_upload: bool
    public_upload_mode: str
    max_uploads_per_hour: int
    max_upload_size_mb: int
    allowed_upload_extensions: list[str]
    web_access_enabled: bool
    web_password_configured: bool
    active_web_sessions: int
    remote_flags: dict[str, bool | None]


class TunnelEndpointDTO(TypedDict):
    active: bool
    url: str


class CloudflareTunnelDTO(TypedDict):
    active: bool
    url: str
    hostname: str


class TunnelSnapshotDTO(TypedDict):
    ssh: TunnelEndpointDTO
    cloudflare: CloudflareTunnelDTO
    any_active: bool


class CloudflareSetupStatusDTO(TypedDict):
    installed: bool
    logged_in: bool
    tunnel_created: bool
    tunnel_id: str | None
    config_written: bool


class PairingSnapshotDTO(TypedDict):
    totp_secret: str
    provisioning_uri: str
    pairing_code: str
    expires_at: float
    ttl_seconds: int
    active: bool
    qr_available: bool


class PairingQrDTO(TypedDict):
    available: bool
    data_url: str | None


class TrustedDeviceDTO(TypedDict):
    device_id: str
    paired_at: float | None
    credential_present: bool
    storage_schema: str
    connected: bool | None


class PendingUploadDTO(TypedDict):
    request_id: str
    filename: str
    size: int
    client: str
    folder: str
    status: str
    created_at: float
    expires_at: float


class ActivitySnapshotDTO(TypedDict):
    pending_uploads: list[PendingUploadDTO]
    existing_log_stream_available: bool
    note: str
    logs: list[dict]
    write_activity: list[dict]
    transfers: list[dict]
    capacity: int


class MetricsSnapshotDTO(TypedDict):
    indexed_files: int
    index_ready: bool
    connected_clients: int
    shared_folder_count: int
    pending_uploads: int
    active_web_sessions: int
    network_addresses: list[str]
    uptime_seconds: float | None
    transfer_speed_bps: float | None
    bandwidth_week_bytes: int | None
    last_connection_at: float | None
    unavailable: list[str]


class ServerSnapshotDTO(TypedDict):
    version: str
    server_name: str
    port: int | None
    websocket_port: int | None
    public_port: int | None
    started_at: float | None
    uptime_seconds: float | None
    shared_roots: list[SharedRootDTO]
    feature_flags: dict[str, bool]
    cluster_role: str
    server_running: bool | None
    websocket_connections: int
    network_addresses: list[str]
