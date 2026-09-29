from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

VALID_STATES = ("new", "triage", "investigating", "waiting-for-evidence", "waiting-for-user", "contained", "monitoring", "resolved", "false-positive")
ALLOWED = {
    "new": {"triage"},
    "triage": {"investigating", "waiting-for-evidence", "waiting-for-user", "false-positive", "resolved"},
    "investigating": {"waiting-for-evidence", "waiting-for-user", "contained", "resolved", "false-positive"},
    "waiting-for-evidence": {"triage", "investigating", "waiting-for-user"},
    "waiting-for-user": {"triage", "investigating", "waiting-for-evidence"},
    "contained": {"investigating", "monitoring", "resolved"},
    "monitoring": {"investigating", "contained", "resolved"},
    "resolved": set(),
    "false-positive": set(),
}


def transition_detail(current: str, target: str, reason: str | None = None) -> str:
    """Keep legacy audit text readable; attach an explicitly supplied rationale."""
    if reason is not None and (not isinstance(reason, str) or not reason.strip()):
        raise ValueError("Transition reason cannot be empty")
    if reason is not None and len(reason) > 2000:
        raise ValueError("Transition reason must be 2000 characters or fewer")
    if target in {"waiting-for-evidence", "waiting-for-user", "monitoring"} and reason is None:
        raise ValueError("A reason is required for waiting and monitoring states")
    return f"{current} -> {target}" + (f" | Reason: {reason.strip()}" if reason else "")


@dataclass(slots=True)
class CaseState:
    case_id: str
    state: str
    owner: str | None
    priority: str
    opened_at: str
    updated_at: str


def new_case(case_id: str, *, priority: str = "P3", owner: str | None = None) -> CaseState:
    now = datetime.now(timezone.utc).isoformat()
    return CaseState(case_id, "new", owner, priority, now, now)


def transition(case: CaseState, target: str, *, reason: str | None = None) -> CaseState:
    if target not in VALID_STATES:
        raise ValueError(f"Unknown case state: {target}")
    if target not in ALLOWED[case.state]:
        raise ValueError(f"Invalid transition: {case.state} -> {target}")
    transition_detail(case.state, target, reason)
    case.state = target
    case.updated_at = datetime.now(timezone.utc).isoformat()
    return case


def assign(case: CaseState, owner: str) -> CaseState:
    case.owner = owner
    case.updated_at = datetime.now(timezone.utc).isoformat()
    return case


def save_case(case: CaseState, path: str | Path) -> None:
    Path(path).write_text(json.dumps(asdict(case), indent=2), encoding="utf-8")


def load_case(path: str | Path) -> CaseState:
    return CaseState(**json.loads(Path(path).read_text(encoding="utf-8")))
