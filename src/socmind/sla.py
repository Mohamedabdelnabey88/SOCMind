from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

DEFAULT_MINUTES = {"P1": 15, "P2": 30, "P3": 120}


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class SLAStatus:
    priority: str
    target_minutes: int
    elapsed_minutes: int
    remaining_minutes: int
    breached: bool
    paused: bool = False
    paused_minutes: int = 0


def evaluate_sla(
    opened_at: str,
    *,
    priority: str,
    now: datetime | None = None,
    paused_seconds: int = 0,
    paused_at: str | None = None,
) -> SLAStatus:
    started = _parse_timestamp(opened_at)
    if started is None:
        raise ValueError("opened_at is required")

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    accumulated_pause = max(0, int(paused_seconds or 0))
    active_pause = 0
    paused_started = _parse_timestamp(paused_at)
    if paused_started is not None:
        active_pause = max(0, int((current - paused_started).total_seconds()))

    total_pause = accumulated_pause + active_pause
    elapsed_seconds = max(0, int((current - started).total_seconds()) - total_pause)
    elapsed = elapsed_seconds // 60
    target = DEFAULT_MINUTES.get(priority.upper(), 120)
    remaining = target - elapsed
    return SLAStatus(
        priority.upper(),
        target,
        elapsed,
        max(0, remaining),
        remaining < 0,
        paused_started is not None,
        total_pause // 60,
    )
