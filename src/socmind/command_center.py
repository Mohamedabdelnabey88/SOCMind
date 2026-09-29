from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .case_workflow import ALLOWED, CaseState, transition_detail
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
    evidence_path: str | None = None


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
    acknowledged_at TEXT,
    evidence_path TEXT
);
CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    author TEXT NOT NULL,
    text TEXT NOT NULL,
    disposition TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    title TEXT NOT NULL,
    severity INTEGER NOT NULL,
    priority TEXT NOT NULL,
    host TEXT NOT NULL,
    user TEXT,
    process TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    technique TEXT,
    rule_id TEXT,
    fingerprint TEXT NOT NULL,
    raw_reference TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_alerts (
    case_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    correlation_score INTEGER NOT NULL,
    correlation_reasons TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY(case_id, alert_id),
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS evidence_requirements (
    requirement_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    label TEXT NOT NULL,
    origin TEXT NOT NULL,
    state TEXT NOT NULL,
    evidence_reference TEXT,
    updated_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requirements_case ON evidence_requirements(case_id, state);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    artifact_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    original_name TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    collector TEXT NOT NULL,
    source TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    storage_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON evidence_artifacts(case_id);

CREATE INDEX IF NOT EXISTS idx_cases_priority_state ON cases(priority,state);
CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner);
CREATE INDEX IF NOT EXISTS idx_notes_case ON case_notes(case_id,created_at);
CREATE INDEX IF NOT EXISTS idx_audit_case ON case_audit(case_id,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_host_time ON alerts(host COLLATE NOCASE,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_user_time ON alerts(user COLLATE NOCASE,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_process_time ON alerts(process COLLATE NOCASE,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_time ON alerts(src_ip,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_time ON alerts(dst_ip,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_time ON alerts(rule_id COLLATE NOCASE,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_technique_time ON alerts(technique COLLATE NOCASE,timestamp);
CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON case_alerts(alert_id);
"""


def _retry_locked(operation, *, attempts: int = 8):
    delay = 0.02
    for attempt in range(attempts):
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.5)


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")

    current_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    if str(current_mode).lower() != "wal":
        _retry_locked(lambda: conn.execute("PRAGMA journal_mode=WAL").fetchone())

    conn.execute("PRAGMA synchronous=NORMAL")
    _retry_locked(lambda: conn.executescript(SCHEMA))

    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(cases)").fetchall()
    }
    for name, sql_type in {
        "acknowledged_at": "TEXT",
        "evidence_path": "TEXT",
    }.items():
        if name not in columns:
            _retry_locked(
                lambda name=name, sql_type=sql_type: conn.execute(
                    f"ALTER TABLE cases ADD COLUMN {name} {sql_type}"
                )
            )
    conn.commit()
    return conn


def upsert_case(
    db_path: str | Path,
    case: CaseState,
    *,
    source: str | None = None,
    title: str | None = None,
    evidence_path: str | Path | None = None,
) -> None:
    evidence = str(Path(evidence_path).resolve()) if evidence_path else None
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO cases(
              case_id,state,priority,owner,opened_at,updated_at,
              source,title,acknowledged_at,evidence_path
            )
            VALUES(?,?,?,?,?,?,?,?,NULL,?)
            ON CONFLICT(case_id) DO UPDATE SET
              state=excluded.state,
              priority=excluded.priority,
              owner=excluded.owner,
              updated_at=excluded.updated_at,
              source=COALESCE(excluded.source,cases.source),
              title=COALESCE(excluded.title,cases.title),
              evidence_path=COALESCE(excluded.evidence_path,cases.evidence_path)
            """,
            (
                case.case_id, case.state, case.priority, case.owner,
                case.opened_at, case.updated_at, source, title, evidence,
            ),
        )
        conn.commit()


def _require_case(conn: sqlite3.Connection, case_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    if row is None:
        raise ValueError(f"Unknown case: {case_id}")
    return row


def acknowledge_case(db_path: str | Path, case_id: str, *, actor: str = "analyst") -> None:
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        _require_case(conn, case_id)
        conn.execute(
            "UPDATE cases SET acknowledged_at=COALESCE(acknowledged_at, ?), updated_at=? WHERE case_id=?",
            (now, now, case_id),
        )
        conn.execute(
            "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(?,?,?,?,?)",
            (case_id, actor, "acknowledged", "Case acknowledged", now),
        )
        conn.commit()


def assign_case(db_path: str | Path, case_id: str, owner: str, *, actor: str = "analyst") -> None:
    now = datetime.now(timezone.utc).isoformat()
    owner = owner.strip()
    if not owner:
        raise ValueError("Owner cannot be empty")
    if len(owner) > 120:
        raise ValueError("Owner must be 120 characters or fewer")
    actor = actor.strip() or "analyst"
    if len(actor) > 120:
        raise ValueError("Actor must be 120 characters or fewer")
    with connect(db_path) as conn:
        _require_case(conn, case_id)
        conn.execute(
            "UPDATE cases SET owner=?, updated_at=? WHERE case_id=?",
            (owner, now, case_id),
        )
        conn.execute(
            "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(?,?,?,?,?)",
            (case_id, actor, "assigned", f"Assigned to {owner}", now),
        )
        conn.commit()


def transition_case(db_path: str | Path, case_id: str, target: str, *, actor: str = "analyst", reason: str | None = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    actor = actor.strip() or "analyst"
    if len(actor) > 120:
        raise ValueError("Actor must be 120 characters or fewer")
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _require_case(conn, case_id)
        current = row["state"]
        if target not in ALLOWED.get(current, set()):
            raise ValueError(f"Invalid transition: {current} -> {target}")
        detail = transition_detail(current, target, reason)
        conn.execute(
            "UPDATE cases SET state=?, updated_at=? WHERE case_id=?",
            (target, now, case_id),
        )
        conn.execute(
            "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(?,?,?,?,?)",
            (case_id, actor, "state-transition", detail, now),
        )
        conn.commit()


def add_case_note(
    db_path: str | Path,
    case_id: str,
    *,
    author: str,
    text: str,
    disposition: str | None = None,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    clean = text.strip()
    if not clean:
        raise ValueError("Note text cannot be empty")
    if len(clean) > 5000:
        raise ValueError("Note text must be 5000 characters or fewer")
    author = author.strip() or "analyst"
    if len(author) > 120:
        raise ValueError("Author must be 120 characters or fewer")
    if disposition is not None and len(str(disposition)) > 80:
        raise ValueError("Disposition must be 80 characters or fewer")
    with connect(db_path) as conn:
        _require_case(conn, case_id)
        cur = conn.execute(
            "INSERT INTO case_notes(case_id,author,text,disposition,created_at) VALUES(?,?,?,?,?)",
            (case_id, author, clean, disposition, now),
        )
        conn.execute(
            "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(?,?,?,?,?)",
            (case_id, author, "note-added", clean[:200], now),
        )
        conn.commit()
        return int(cur.lastrowid)


def case_detail(db_path: str | Path, case_id: str) -> dict:
    with connect(db_path) as conn:
        case = dict(_require_case(conn, case_id))
        notes = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
        ]
        audit = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM case_audit WHERE case_id=? ORDER BY timestamp DESC",
                (case_id,),
            ).fetchall()
        ]
        alerts = [
            dict(row)
            for row in conn.execute(
                """
                SELECT
                  a.*,
                  ca.correlation_score,
                  ca.correlation_reasons,
                  ca.linked_at
                FROM case_alerts ca
                JOIN alerts a ON a.alert_id=ca.alert_id
                WHERE ca.case_id=?
                ORDER BY a.timestamp ASC
                """,
                (case_id,),
            ).fetchall()
        ]
        for item in alerts:
            try:
                item["correlation_reasons"] = json.loads(item["correlation_reasons"])
            except (TypeError, json.JSONDecodeError):
                item["correlation_reasons"] = []
    return {"case": case, "notes": notes, "audit": audit, "alerts": alerts, "allowed_transitions": sorted(ALLOWED.get(case["state"], set()))}


def list_cases(
    db_path: str | Path,
    *,
    query: str | None = None,
    priority: str | None = None,
    state: str | None = None,
    owner: str | None = None,
) -> list[CommandCase]:
    sql = "SELECT * FROM cases WHERE 1=1"
    params: list[str] = []
    if query:
        sql += " AND (case_id LIKE ? OR COALESCE(title,'') LIKE ? OR COALESCE(source,'') LIKE ?)"
        needle = f"%{query}%"
        params += [needle, needle, needle]
    if priority:
        sql += " AND priority=?"
        params.append(priority)
    if state:
        sql += " AND state=?"
        params.append(state)
    if owner:
        if owner == "Unassigned":
            sql += " AND owner IS NULL"
        else:
            sql += " AND owner=?"
            params.append(owner)
    sql += " ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END, opened_at"

    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [CommandCase(**dict(row)) for row in rows]


def command_center_snapshot(
    db_path: str | Path,
    *,
    query: str | None = None,
    priority: str | None = None,
    state: str | None = None,
    owner: str | None = None,
) -> dict:
    all_cases = list_cases(db_path)
    cases = list_cases(db_path, query=query, priority=priority, state=state, owner=owner)
    active_all = [c for c in all_cases if c.state not in {"resolved", "false-positive"}]
    breached = []
    for case in active_all:
        status = evaluate_sla(case.opened_at, priority=case.priority)
        if status.breached:
            breached.append(case.case_id)

    owner_counts: dict[str, int] = {}
    for case in active_all:
        key = case.owner or "Unassigned"
        owner_counts[key] = owner_counts.get(key, 0) + 1

    acknowledged = [c for c in all_cases if c.acknowledged_at]
    mtta_values = []
    for case in acknowledged:
        opened = datetime.fromisoformat(case.opened_at.replace("Z", "+00:00"))
        ack = datetime.fromisoformat(case.acknowledged_at.replace("Z", "+00:00"))
        mtta_values.append(max(0, int((ack - opened).total_seconds() // 60)))

    resolved = [c for c in all_cases if c.state == "resolved"]
    mttr_values = []
    for case in resolved:
        opened = datetime.fromisoformat(case.opened_at.replace("Z", "+00:00"))
        closed = datetime.fromisoformat(case.updated_at.replace("Z", "+00:00"))
        mttr_values.append(max(0, int((closed - opened).total_seconds() // 60)))

    active_filtered = [c for c in cases if c.state not in {"resolved", "false-positive"}]
    sla_by_case = {
        c.case_id: evaluate_sla(c.opened_at, priority=c.priority)
        for c in active_filtered
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(all_cases),
            "active": len(active_all),
            "p1_active": sum(1 for c in active_all if c.priority == "P1"),
            "unassigned": sum(1 for c in active_all if not c.owner),
            "sla_breached": len(breached),
            "resolved": len(resolved),
            "mtta_minutes": round(sum(mtta_values) / len(mtta_values), 1) if mtta_values else None,
            "mttr_minutes": round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None,
        },
        "filters": {"query": query, "priority": priority, "state": state, "owner": owner},
        "sla_breaches": breached,
        "workload": [
            {"owner": key, "active_cases": count}
            for key, count in sorted(owner_counts.items(), key=lambda item: (-item[1], item[0]))
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
                "acknowledged_at": c.acknowledged_at,
                "has_evidence": bool(c.evidence_path),
                "sla": {
                    "breached": sla_by_case[c.case_id].breached,
                    "remaining_minutes": sla_by_case[c.case_id].remaining_minutes,
                } if c.case_id in sla_by_case else None,
            }
            for c in cases
        ],
    }
