from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

VALID_STATES = ("new", "triage", "investigating", "contained", "resolved", "false-positive")
ALLOWED = {
    "new": {"triage"},
    "triage": {"investigating", "false-positive", "resolved"},
    "investigating": {"contained", "resolved", "false-positive"},
    "contained": {"resolved"},
    "resolved": set(),
    "false-positive": set(),
}


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


def transition(case: CaseState, target: str) -> CaseState:
    if target not in VALID_STATES:
        raise ValueError(f"Unknown case state: {target}")
    if target not in ALLOWED[case.state]:
        raise ValueError(f"Invalid transition: {case.state} -> {target}")
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
