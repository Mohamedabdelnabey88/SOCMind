from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .case_workflow import ALLOWED, CLOSED_STATES, PAUSED_STATES, CaseState, state_history_from_audit
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
    sla_paused_at: str | None = None
    sla_paused_seconds: int = 0


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
    evidence_path TEXT,
    sla_paused_at TEXT,
    sla_paused_seconds INTEGER NOT NULL DEFAULT 0
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
CREATE TABLE IF NOT EXISTS evidence_collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collection_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    query_json TEXT NOT NULL,
    status TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    total_hits INTEGER,
    truncated INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);
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
CREATE TABLE IF NOT EXISTS evidence_requirements (
    requirement_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    key TEXT NOT NULL,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    target TEXT,
    rationale TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    assigned_to TEXT,
    due_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    received_at TEXT,
    response_summary TEXT,
    evidence_reference TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_evidence_collections_case ON evidence_collections(case_id,started_at);
CREATE INDEX IF NOT EXISTS idx_evidence_requirements_case ON evidence_requirements(case_id,created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_requirements_status ON evidence_requirements(status,due_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_requirements_open_key
ON evidence_requirements(case_id,key)
WHERE status IN ('required','requested');
"""


def _retry_locked(operation, *, attempts: int = 20):
    for attempt in range(attempts):
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            time.sleep(min(0.05 * (attempt + 1), 0.5))


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")

    def configure_journal():
        mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if mode != "wal":
            conn.execute("PRAGMA journal_mode=WAL")

    _retry_locked(configure_journal)
    conn.execute("PRAGMA synchronous=NORMAL")
    _retry_locked(lambda: conn.executescript(SCHEMA))
    columns = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    for name, sql_type in {
        "acknowledged_at": "TEXT",
        "evidence_path": "TEXT",
        "sla_paused_at": "TEXT",
        "sla_paused_seconds": "INTEGER NOT NULL DEFAULT 0",
    }.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE cases ADD COLUMN {name} {sql_type}")
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
              source,title,acknowledged_at,evidence_path,
              sla_paused_at,sla_paused_seconds
            )
            VALUES(?,?,?,?,?,?,?,?,NULL,?,?,?)
            ON CONFLICT(case_id) DO UPDATE SET
              state=excluded.state,
              priority=excluded.priority,
              owner=excluded.owner,
              updated_at=excluded.updated_at,
              source=COALESCE(excluded.source,cases.source),
              title=COALESCE(excluded.title,cases.title),
              evidence_path=COALESCE(excluded.evidence_path,cases.evidence_path),
              sla_paused_at=excluded.sla_paused_at,
              sla_paused_seconds=excluded.sla_paused_seconds
            """,
            (
                case.case_id, case.state, case.priority, case.owner,
                case.opened_at, case.updated_at, source, title, evidence,
                case.sla_paused_at, max(0, int(case.sla_paused_seconds)),
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


def transition_case(
    db_path: str | Path,
    case_id: str,
    target: str,
    *,
    actor: str = "analyst",
    reason: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    actor = actor.strip() or "analyst"
    if len(actor) > 120:
        raise ValueError("Actor must be 120 characters or fewer")
    clean_reason = str(reason or "").strip()
    if len(clean_reason) > 1000:
        raise ValueError("Transition reason must be 1000 characters or fewer")
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _require_case(conn, case_id)
        current = row["state"]
        if target not in ALLOWED.get(current, set()):
            raise ValueError(f"Invalid transition: {current} -> {target}")

        paused_at = row["sla_paused_at"]
        paused_seconds = max(0, int(row["sla_paused_seconds"] or 0))
        was_paused = current in PAUSED_STATES
        will_pause = target in PAUSED_STATES

        if was_paused and not will_pause:
            if paused_at:
                started = datetime.fromisoformat(str(paused_at).replace("Z", "+00:00"))
                paused_seconds += max(
                    0,
                    int((datetime.fromisoformat(now) - started).total_seconds()),
                )
            paused_at = None
        elif not was_paused and will_pause:
            paused_at = now
        elif was_paused and will_pause and not paused_at:
            paused_at = now

        conn.execute(
            """
            UPDATE cases
            SET state=?, updated_at=?, sla_paused_at=?, sla_paused_seconds=?
            WHERE case_id=?
            """,
            (target, now, paused_at, paused_seconds, case_id),
        )
        detail = f"{current} -> {target}"
        if clean_reason:
            detail += f" | reason: {clean_reason}"
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


def record_case_activity(
    db_path: str | Path,
    case_id: str,
    *,
    activity: str,
    actor: str,
    detail: str,
) -> None:
    allowed = {"escalation", "detection-feedback"}
    clean_activity = str(activity or "").strip().lower()
    if clean_activity not in allowed:
        raise ValueError(f"Unsupported case activity: {clean_activity}")
    clean_actor = str(actor or "").strip() or "analyst"
    clean_detail = str(detail or "").strip()
    if not clean_detail:
        raise ValueError("Activity detail cannot be empty")
    if len(clean_actor) > 120:
        raise ValueError("Actor must be 120 characters or fewer")
    if len(clean_detail) > 5000:
        raise ValueError("Activity detail must be 5000 characters or fewer")
    now = datetime.now(timezone.utc).isoformat()
    action = "escalated" if clean_activity == "escalation" else "detection-feedback-recorded"
    with connect(db_path) as conn:
        _require_case(conn, case_id)
        conn.execute(
            "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(?,?,?,?,?)",
            (case_id, clean_actor, action, clean_detail, now),
        )
        conn.commit()


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
        state_history = state_history_from_audit(audit)
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
        collections = [
            dict(row)
            for row in conn.execute(
                """
                SELECT * FROM evidence_collections
                WHERE case_id=?
                ORDER BY started_at DESC
                """,
                (case_id,),
            ).fetchall()
        ]
        for item in collections:
            try:
                item["query"] = json.loads(item.pop("query_json"))
            except (TypeError, json.JSONDecodeError):
                item["query"] = {}
        requirements = [
            dict(row)
            for row in conn.execute(
                """
                SELECT * FROM evidence_requirements
                WHERE case_id=?
                ORDER BY created_at ASC
                """,
                (case_id,),
            ).fetchall()
        ]
    return {
        "case": case,
        "notes": notes,
        "audit": audit,
        "state_history": state_history,
        "alerts": alerts,
        "evidence_collections": collections,
        "evidence_requirements": requirements,
    }


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
    active_all = [c for c in all_cases if c.state not in CLOSED_STATES]
    breached = []
    for case in active_all:
        status = evaluate_sla(
            case.opened_at,
            priority=case.priority,
            paused_seconds=case.sla_paused_seconds,
            paused_at=case.sla_paused_at,
        )
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

    now_iso = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        requirement_rows = conn.execute(
            """
            SELECT case_id,status,due_at
            FROM evidence_requirements
            WHERE status IN ('required','requested')
            """
        ).fetchall()
    requirement_counts: dict[str, dict[str, int]] = {}
    for row in requirement_rows:
        bucket = requirement_counts.setdefault(
            str(row["case_id"]),
            {"open": 0, "overdue": 0},
        )
        bucket["open"] += 1
        if row["due_at"] and str(row["due_at"]) < now_iso:
            bucket["overdue"] += 1

    active_filtered = [c for c in cases if c.state not in CLOSED_STATES]
    sla_by_case = {
        c.case_id: evaluate_sla(
            c.opened_at,
            priority=c.priority,
            paused_seconds=c.sla_paused_seconds,
            paused_at=c.sla_paused_at,
        )
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
            "sla_paused": sum(1 for c in active_all if c.state in PAUSED_STATES),
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
                "evidence_requirements": requirement_counts.get(
                    c.case_id,
                    {"open": 0, "overdue": 0},
                ),
                "sla": {
                    "breached": sla_by_case[c.case_id].breached,
                    "remaining_minutes": sla_by_case[c.case_id].remaining_minutes,
                    "paused": sla_by_case[c.case_id].paused,
                    "paused_minutes": sla_by_case[c.case_id].paused_minutes,
                } if c.case_id in sla_by_case else None,
            }
            for c in cases
        ],
    }
