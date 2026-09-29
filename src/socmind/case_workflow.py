from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

VALID_STATES = (
    "new",
    "triage",
    "investigating",
    "waiting-for-evidence",
    "waiting-for-user",
    "contained",
    "monitoring",
    "resolved",
    "false-positive",
)
PAUSED_STATES = {"waiting-for-evidence", "waiting-for-user"}
CLOSED_STATES = {"resolved", "false-positive"}

ALLOWED = {
    "new": {"triage"},
    "triage": {
        "investigating",
        "waiting-for-evidence",
        "waiting-for-user",
        "resolved",
        "false-positive",
    },
    "investigating": {
        "waiting-for-evidence",
        "waiting-for-user",
        "contained",
        "monitoring",
        "resolved",
        "false-positive",
    },
    "waiting-for-evidence": {
        "triage",
        "investigating",
        "waiting-for-user",
        "monitoring",
        "resolved",
        "false-positive",
    },
    "waiting-for-user": {
        "triage",
        "investigating",
        "waiting-for-evidence",
        "monitoring",
        "resolved",
        "false-positive",
    },
    "contained": {"investigating", "monitoring", "resolved"},
    "monitoring": {
        "investigating",
        "waiting-for-evidence",
        "waiting-for-user",
        "contained",
        "resolved",
        "false-positive",
    },
    "resolved": set(),
    "false-positive": set(),
}


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(slots=True)
class CaseState:
    case_id: str
    state: str
    owner: str | None
    priority: str
    opened_at: str
    updated_at: str
    sla_paused_at: str | None = None
    sla_paused_seconds: int = 0


def new_case(case_id: str, *, priority: str = "P3", owner: str | None = None) -> CaseState:
    now = datetime.now(timezone.utc).isoformat()
    return CaseState(case_id, "new", owner, priority, now, now)


def transition(
    case: CaseState,
    target: str,
    *,
    now: datetime | None = None,
) -> CaseState:
    if target not in VALID_STATES:
        raise ValueError(f"Unknown case state: {target}")
    if target not in ALLOWED.get(case.state, set()):
        raise ValueError(f"Invalid transition: {case.state} -> {target}")

    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    was_paused = case.state in PAUSED_STATES
    will_pause = target in PAUSED_STATES

    if was_paused and not will_pause:
        paused_at = _parse_timestamp(case.sla_paused_at)
        if paused_at is not None:
            case.sla_paused_seconds += max(
                0,
                int((current_time - paused_at).total_seconds()),
            )
        case.sla_paused_at = None
    elif not was_paused and will_pause:
        case.sla_paused_at = current_time.isoformat()
    elif was_paused and will_pause and case.sla_paused_at is None:
        # Repairs legacy/incomplete paused cases without resetting accumulated time.
        case.sla_paused_at = current_time.isoformat()

    case.state = target
    case.updated_at = current_time.isoformat()
    return case


def assign(case: CaseState, owner: str) -> CaseState:
    case.owner = owner
    case.updated_at = datetime.now(timezone.utc).isoformat()
    return case


def save_case(case: CaseState, path: str | Path) -> None:
    Path(path).write_text(json.dumps(asdict(case), indent=2), encoding="utf-8")


def load_case(path: str | Path) -> CaseState:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    payload.setdefault("sla_paused_at", None)
    payload.setdefault("sla_paused_seconds", 0)
    return CaseState(**payload)
