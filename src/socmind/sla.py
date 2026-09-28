from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

DEFAULT_MINUTES = {"P1": 15, "P2": 30, "P3": 120}


@dataclass(frozen=True, slots=True)
class SLAStatus:
    priority: str
    target_minutes: int
    elapsed_minutes: int
    remaining_minutes: int
    breached: bool


def evaluate_sla(opened_at: str, *, priority: str, now: datetime | None = None) -> SLAStatus:
    started = datetime.fromisoformat(opened_at.replace("Z", "+00:00"))
    current = now or datetime.now(timezone.utc)
    elapsed = max(0, int((current - started).total_seconds() // 60))
    target = DEFAULT_MINUTES.get(priority.upper(), 120)
    remaining = target - elapsed
    return SLAStatus(priority.upper(), target, elapsed, max(0, remaining), remaining < 0)
