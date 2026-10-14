"""Hardware-bounded in-process resource policy for the Performance hub."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class WorkerBudget:
    cpu_count_logical: int
    hard_total: int
    index_workers: int
    analysis_workers: int
    adjusted: str | None = None


def logical_cpu_count(detector=os.cpu_count) -> int:
    return max(1, int(detector() or 1))


def hard_worker_total(cpu_count_logical: int) -> int:
    """Reserve one logical CPU for the Server/UI."""
    return max(1, int(cpu_count_logical) - 1)


def preset_worker_values(preset: str, cpu_count_logical: int) -> tuple[int, int]:
    """Return starting values; clamp_worker_budget remains the final authority."""
    total = hard_worker_total(cpu_count_logical)
    if preset == "economy":
        return 1, 1
    if preset == "balanced_light":
        return min(2, total), 1
    if preset == "performance":
        analysis = max(1, total // 3)
        return max(1, total - analysis), analysis
    return min(4, max(2, total - 1)), min(2, max(1, total - min(4, max(2, total - 1))))


def clamp_worker_budget(
    index_workers: object,
    analysis_workers: object,
    cpu_count_logical: int,
    *,
    changed: str = "index",
) -> WorkerBudget:
    """Clamp hostile inputs and reduce the counterpart when the total is exceeded."""
    cpu_count = max(1, int(cpu_count_logical or 1))
    hard_total = hard_worker_total(cpu_count)

    def bounded(value: object) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError, OverflowError):
            parsed = 1
        return min(hard_total, max(1, parsed))

    index_value = bounded(index_workers)
    analysis_value = bounded(analysis_workers)
    adjusted = None
    overflow = index_value + analysis_value - hard_total
    if overflow > 0:
        counterpart = "analysis" if changed == "index" else "index"
        if counterpart == "analysis":
            reduced = max(1, analysis_value - overflow)
            overflow -= analysis_value - reduced
            analysis_value = reduced
        else:
            reduced = max(1, index_value - overflow)
            overflow -= index_value - reduced
            index_value = reduced
        if overflow > 0:
            if changed == "index":
                index_value = max(1, index_value - overflow)
            else:
                analysis_value = max(1, analysis_value - overflow)
        adjusted = counterpart

    # A one- or two-thread host cannot satisfy both per-pool minimums and the
    # reserved-CPU sum simultaneously. Keep the safe serialized minimum and
    # expose hard_total=1; runtime coordination prevents concurrent activity.
    if hard_total < 2:
        index_value = analysis_value = 1
        adjusted = "serialized"

    return WorkerBudget(
        cpu_count_logical=cpu_count,
        hard_total=hard_total,
        index_workers=index_value,
        analysis_workers=analysis_value,
        adjusted=adjusted,
    )


def effective_worker_budget(
    preset: str,
    cpu_count_logical: int,
    index_workers: object = None,
    analysis_workers: object = None,
) -> WorkerBudget:
    defaults = preset_worker_values(preset, cpu_count_logical)
    return clamp_worker_budget(
        defaults[0] if index_workers is None else index_workers,
        defaults[1] if analysis_workers is None else analysis_workers,
        cpu_count_logical,
        changed="index",
    )


def analysis_queue_limit(preset: str, cpu_count_logical: int) -> int:
    """Bound queued audio work by both preset and detected hardware."""
    hard_limit = max(16, logical_cpu_count(lambda: cpu_count_logical) * 32)
    requested = {
        "economy": 16,
        "balanced_light": 64,
        "balanced": 128,
        "performance": hard_limit,
    }.get(preset, 128)
    return min(hard_limit, requested)


def watcher_limits(preset: str, cpu_count_logical: int) -> tuple[int, int]:
    """Return (batch per tick, bounded coalescing capacity)."""
    hard_batch = max(8, logical_cpu_count(lambda: cpu_count_logical) * 8)
    requested = {
        "economy": 8,
        "balanced_light": 16,
        "balanced": 32,
        "performance": hard_batch,
    }.get(preset, 32)
    batch = min(hard_batch, requested)
    # macOS FSEvents can deliver a legitimate directory burst much faster than
    # the 50 ms drain cadence.  Keep the queue bounded, but give it enough room
    # to absorb short bursts instead of immediately forcing a full index rebuild.
    capacity = min(8192, max(1024, batch * 64))
    return batch, capacity
