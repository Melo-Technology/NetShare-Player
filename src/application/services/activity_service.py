"""Non-destructive activity/log access backed by producer-side fan-out."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from src.constants import VERSION

from ..adapters import StateAdapter
from ..dto import ActivitySnapshotDTO, PendingUploadDTO
from ..exceptions import ApplicationNotFoundError, ApplicationValidationError
from .base import BaseApplicationService


class ActivityService(BaseApplicationService):
    service_name = "activity"

    def __init__(self, state: StateAdapter | None = None, logger=None, *, activity_runtime=None):
        self.state = state or StateAdapter()
        if activity_runtime is None:
            from src.runtime.activity_runtime import activity_runtime
        self.activity_runtime = activity_runtime
        super().__init__(logger)

    @staticmethod
    def _pending_dto(item: dict) -> PendingUploadDTO:
        return PendingUploadDTO(
            request_id=str(item.get("id") or ""), filename=str(item.get("filename") or ""),
            size=max(0, int(item.get("size") or 0)), client=str(item.get("client") or ""),
            folder=str(item.get("folder") or "/incoming"), status=str(item.get("status") or "pending"),
            created_at=float(item.get("created_at") or 0.0), expires_at=float(item.get("expires_at") or 0.0),
        )

    def snapshot(self, *, correlation_id=None) -> ActivitySnapshotDTO:
        def load():
            pending = [self._pending_dto(item) for item in self.state.pending_uploads()]
            live = self.activity_runtime.snapshot()
            return ActivitySnapshotDTO(
                pending_uploads=pending,
                existing_log_stream_available=True,
                note="producer-side fan-out; legacy Tkinter queues remain single-consumer",
                logs=list(live["logs"]),
                write_activity=list(live["write_activity"]),
                transfers=list(live.get("transfers", [])),
                capacity=int(live["capacity"]),
            )
        return self._execute("snapshot", load, correlation_id=correlation_id)

    def resolve_upload(self, request_id: str, accepted: bool, *, correlation_id=None) -> PendingUploadDTO:
        def apply():
            item = self.state.resolve_upload(str(request_id), bool(accepted))
            if item is None:
                raise ApplicationNotFoundError("upload request not found", code="activity.upload.not_found", details={"request_id": str(request_id)[:128]})
            return self._pending_dto(item)
        return self._execute("resolve_upload", apply, correlation_id=correlation_id)

    def export_logs(self, target_path: str, *, correlation_id=None) -> dict:
        clean = str(target_path or "").strip()
        if not clean:
            raise ApplicationValidationError("target path required", code="activity.export.path_required")
        def apply():
            snapshot = self.activity_runtime.snapshot()
            lines=[]
            for entry in snapshot["logs"]:
                stamp=datetime.fromtimestamp(float(entry.get("time") or 0)).strftime("%H:%M:%S")
                lines.append(f"[{stamp}]  [{str(entry.get('kind') or 'info').upper()}]  {entry.get('message','')}")
            if not lines:
                raise ApplicationValidationError("no logs to export", code="activity.export.empty")
            target=Path(clean)
            header=(f"NetShare Player Server {VERSION}\n"
                    f"Exported: {datetime.now().isoformat(timespec='seconds')}\n"
                    f"Bounded export: latest {int(snapshot['capacity'])} buffered records at most.\n"
                    f"{'='*72}\n")
            target.write_text(header+"\n".join(lines)+"\n",encoding="utf-8")
            return {"path": str(target), "records": len(lines)}
        return self._execute("export_logs", apply, correlation_id=correlation_id)
