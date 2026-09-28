from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .case_workflow import CaseState
from .sla import evaluate_sla


@dataclass(frozen=True, slots=True)
class CommandCase:
    case_id: str
    state: str
    priority: str
    owner: str | None
    opened_at: str
    updated_at: str
    source: str | None = None
    title: str | None = None
    acknowledged_at: str | None = None


SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    priority TEXT NOT NULL,
    owner TEXT,
    opened_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    source TEXT,
    title TEXT,
    acknowledged_at TEXT
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if "acknowledged_at" not in columns:
        conn.execute("ALTER TABLE cases ADD COLUMN acknowledged_at TEXT")
    conn.commit()
    return conn


def upsert_case(
    db_path: str | Path,
    case: CaseState,
    *,
    source: str | None = None,
    title: str | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO cases(case_id,state,priority,owner,opened_at,updated_at,source,title,acknowledged_at)
            VALUES(?,?,?,?,?,?,?,?,NULL)
            ON CONFLICT(case_id) DO UPDATE SET
              state=excluded.state,
              priority=excluded.priority,
              owner=excluded.owner,
              updated_at=excluded.updated_at,
              source=COALESCE(excluded.source,cases.source),
              title=COALESCE(excluded.title,cases.title)
            """,
            (
                case.case_id,
                case.state,
                case.priority,
                case.owner,
                case.opened_at,
                case.updated_at,
                source,
                title,
            ),
        )
        conn.commit()


def acknowledge_case(db_path: str | Path, case_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        result = conn.execute(
            "UPDATE cases SET acknowledged_at=COALESCE(acknowledged_at, ?), updated_at=? WHERE case_id=?",
            (now, now, case_id),
        )
        if result.rowcount == 0:
            raise ValueError(f"Unknown case: {case_id}")
        conn.commit()


def list_cases(db_path: str | Path) -> list[CommandCase]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM cases ORDER BY "
            "CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END, opened_at"
        ).fetchall()
    return [CommandCase(**dict(row)) for row in rows]


def command_center_snapshot(db_path: str | Path) -> dict:
    cases = list_cases(db_path)
    active = [c for c in cases if c.state not in {"resolved", "false-positive"}]
    breached = []
    for case in active:
        status = evaluate_sla(case.opened_at, priority=case.priority)
        if status.breached:
            breached.append(case.case_id)

    owner_counts: dict[str, int] = {}
    for case in active:
        owner = case.owner or "Unassigned"
        owner_counts[owner] = owner_counts.get(owner, 0) + 1

    now = datetime.now(timezone.utc)
    acknowledged = [c for c in cases if c.acknowledged_at]
    mtta_values = []
    for case in acknowledged:
        opened = datetime.fromisoformat(case.opened_at.replace("Z", "+00:00"))
        ack = datetime.fromisoformat(case.acknowledged_at.replace("Z", "+00:00"))
        mtta_values.append(max(0, int((ack - opened).total_seconds() // 60)))

    resolved = [c for c in cases if c.state == "resolved"]
    mttr_values = []
    for case in resolved:
        opened = datetime.fromisoformat(case.opened_at.replace("Z", "+00:00"))
        closed = datetime.fromisoformat(case.updated_at.replace("Z", "+00:00"))
        mttr_values.append(max(0, int((closed - opened).total_seconds() // 60)))

    return {
        "generated_at": now.isoformat(),
        "summary": {
            "total": len(cases),
            "active": len(active),
            "p1_active": sum(1 for c in active if c.priority == "P1"),
            "unassigned": sum(1 for c in active if not c.owner),
            "sla_breached": len(breached),
            "resolved": len(resolved),
            "mtta_minutes": round(sum(mtta_values) / len(mtta_values), 1) if mtta_values else None,
            "mttr_minutes": round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None,
        },
        "sla_breaches": breached,
        "workload": [
            {"owner": owner, "active_cases": count}
            for owner, count in sorted(owner_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        "queue": [
            {
                "case_id": c.case_id,
                "title": c.title or c.case_id,
                "state": c.state,
                "priority": c.priority,
                "owner": c.owner,
                "source": c.source,
                "opened_at": c.opened_at,
                "updated_at": c.updated_at,
                "sla": {
                    "breached": evaluate_sla(c.opened_at, priority=c.priority).breached,
                    "remaining_minutes": evaluate_sla(c.opened_at, priority=c.priority).remaining_minutes,
                } if c.state not in {"resolved", "false-positive"} else None,
            }
            for c in cases
        ],
    }
