"""Trusted-device projections and local-pairing orchestration."""

from __future__ import annotations

from ..adapters import RuntimeAdapter, StateAdapter
from ..dto import PairingQrDTO, PairingSnapshotDTO, TrustedDeviceDTO
from ..exceptions import ApplicationNotFoundError
from .base import BaseApplicationService


class DeviceService(BaseApplicationService):
    service_name = "devices"

    def __init__(self, state: StateAdapter | None = None, runtime: RuntimeAdapter | None = None, logger=None, *, pairing_runtime=None):
        self.state = state or StateAdapter()
        self.runtime = runtime or RuntimeAdapter(self.state.state)
        if pairing_runtime is None:
            from src.runtime.pairing_runtime import pairing_runtime_controller
            pairing_runtime = pairing_runtime_controller
        self.pairing_runtime = pairing_runtime
        super().__init__(logger)

    @staticmethod
    def _normalize(device_id: str, record, connected_ids: set[str]) -> TrustedDeviceDTO:
        paired_at = None
        credential_present = False
        storage_schema = "unknown"
        if isinstance(record, dict):
            storage_schema = "credential_v2"
            try:
                raw = record.get("paired_at")
                paired_at = float(raw) if raw is not None else None
            except (TypeError, ValueError):
                paired_at = None
            credential_present = bool(record.get("credential_hash"))
        else:
            storage_schema = "legacy_timestamp"
            try:
                paired_at = float(record)
            except (TypeError, ValueError):
                paired_at = None
        return TrustedDeviceDTO(
            device_id=str(device_id), paired_at=paired_at,
            credential_present=credential_present, storage_schema=storage_schema,
            connected=str(device_id) in connected_ids,
        )

    def list_trusted_devices(self, *, correlation_id=None) -> list[TrustedDeviceDTO]:
        def load():
            records = self.state.trusted_devices()
            connected = self.runtime.connected_device_ids()
            return [self._normalize(device_id, record, connected) for device_id, record in sorted(records.items())]
        return self._execute("list_trusted_devices", load, correlation_id=correlation_id)

    def pairing_snapshot(self, *, correlation_id=None) -> PairingSnapshotDTO:
        return self._execute("pairing_snapshot", lambda: PairingSnapshotDTO(**self.pairing_runtime.snapshot()), correlation_id=correlation_id)

    def start_pairing(self, *, correlation_id=None) -> PairingSnapshotDTO:
        return self._execute("start_pairing", lambda: PairingSnapshotDTO(**self.pairing_runtime.start_pairing()), correlation_id=correlation_id)

    def expire_pairing(self, *, correlation_id=None) -> PairingSnapshotDTO:
        return self._execute("expire_pairing", lambda: PairingSnapshotDTO(**self.pairing_runtime.expire_pairing()), correlation_id=correlation_id)

    def pairing_qr(self, *, correlation_id=None) -> PairingQrDTO:
        def load():
            value = self.pairing_runtime.qr_data_url()
            return PairingQrDTO(available=bool(value), data_url=value)
        return self._execute("pairing_qr", load, correlation_id=correlation_id)

    def revoke_device(self, device_id: str, *, correlation_id=None) -> bool:
        clean = str(device_id or "").strip()
        def apply():
            if clean not in self.state.trusted_devices():
                raise ApplicationNotFoundError("trusted device not found", code="devices.not_found", details={"device_id": clean[:128]})
            self.state.revoke_device(clean)
            return True
        return self._execute("revoke_device", apply, correlation_id=correlation_id)
