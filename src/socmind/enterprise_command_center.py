from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .case_workflow import ALLOWED, CLOSED_STATES, PAUSED_STATES, CaseState, state_history_from_audit
from .postgres_store import _psycopg, initialize_postgres
from .sla import evaluate_sla


@dataclass(frozen=True, slots=True)
class EnterpriseCase:
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


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _row_to_case(row: dict) -> EnterpriseCase:
    return EnterpriseCase(
        case_id=row["case_id"],
        state=row["state"],
        priority=row["priority"],
        owner=row.get("owner"),
        opened_at=_iso(row["opened_at"]) or "",
        updated_at=_iso(row["updated_at"]) or "",
        source=row.get("source"),
        title=row.get("title"),
        acknowledged_at=_iso(row.get("acknowledged_at")),
        evidence_path=row.get("evidence_path"),
        sla_paused_at=_iso(row.get("sla_paused_at")),
        sla_paused_seconds=max(0, int(row.get("sla_paused_seconds") or 0)),
    )


def _connect(dsn: str):
    psycopg = _psycopg()
    from psycopg.rows import dict_row
    return psycopg.connect(dsn, row_factory=dict_row)


def upsert_case_pg(
    dsn: str,
    case: CaseState,
    *,
    source: str | None = None,
    title: str | None = None,
    evidence_path: str | None = None,
) -> None:
    initialize_postgres(dsn)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cases(
                  case_id,state,priority,owner,opened_at,updated_at,
                  source,title,acknowledged_at,evidence_path,
                  sla_paused_at,sla_paused_seconds
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,%s)
                ON CONFLICT(case_id) DO UPDATE SET
                  state=EXCLUDED.state,
                  priority=EXCLUDED.priority,
                  owner=EXCLUDED.owner,
                  updated_at=EXCLUDED.updated_at,
                  source=COALESCE(EXCLUDED.source,cases.source),
                  title=COALESCE(EXCLUDED.title,cases.title),
                  evidence_path=COALESCE(EXCLUDED.evidence_path,cases.evidence_path),
                  sla_paused_at=EXCLUDED.sla_paused_at,
                  sla_paused_seconds=EXCLUDED.sla_paused_seconds
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
                    evidence_path,
                    case.sla_paused_at,
                    max(0, int(case.sla_paused_seconds)),
                ),
            )
        conn.commit()


def _require_case(cur, case_id: str, *, for_update: bool = False) -> dict:
    sql = "SELECT * FROM cases WHERE case_id=%s"
    if for_update:
        sql += " FOR UPDATE"
    cur.execute(sql, (case_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Unknown case: {case_id}")
    return row


def acknowledge_case_pg(
    dsn: str,
    case_id: str,
    *,
    actor: str = "analyst",
) -> None:
    now = datetime.now(timezone.utc)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            _require_case(cur, case_id)
            cur.execute(
                """
                UPDATE cases
                SET acknowledged_at=COALESCE(acknowledged_at,%s), updated_at=%s
                WHERE case_id=%s
                """,
                (now, now, case_id),
            )
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (case_id, actor, "acknowledged", "Case acknowledged", now),
            )
        conn.commit()


def assign_case_pg(
    dsn: str,
    case_id: str,
    owner: str,
    *,
    actor: str = "analyst",
) -> None:
    owner = owner.strip()
    actor = actor.strip() or "analyst"
    if not owner:
        raise ValueError("Owner cannot be empty")
    if len(owner) > 120:
        raise ValueError("Owner must be 120 characters or fewer")
    if len(actor) > 120:
        raise ValueError("Actor must be 120 characters or fewer")
    now = datetime.now(timezone.utc)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            _require_case(cur, case_id)
            cur.execute(
                "UPDATE cases SET owner=%s, updated_at=%s WHERE case_id=%s",
                (owner, now, case_id),
            )
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (case_id, actor, "assigned", f"Assigned to {owner}", now),
            )
        conn.commit()


def transition_case_pg(
    dsn: str,
    case_id: str,
    target: str,
    *,
    actor: str = "analyst",
    reason: str | None = None,
) -> None:
    actor = actor.strip() or "analyst"
    if len(actor) > 120:
        raise ValueError("Actor must be 120 characters or fewer")
    clean_reason = str(reason or "").strip()
    if len(clean_reason) > 1000:
        raise ValueError("Transition reason must be 1000 characters or fewer")
    now = datetime.now(timezone.utc)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            row = _require_case(cur, case_id, for_update=True)
            current = row["state"]
            if target not in ALLOWED.get(current, set()):
                raise ValueError(f"Invalid transition: {current} -> {target}")

            paused_at = row.get("sla_paused_at")
            paused_seconds = max(0, int(row.get("sla_paused_seconds") or 0))
            was_paused = current in PAUSED_STATES
            will_pause = target in PAUSED_STATES

            if was_paused and not will_pause:
                if paused_at is not None:
                    paused_seconds += max(
                        0,
                        int((now - paused_at).total_seconds()),
                    )
                paused_at = None
            elif not was_paused and will_pause:
                paused_at = now
            elif was_paused and will_pause and paused_at is None:
                paused_at = now

            cur.execute(
                """
                UPDATE cases
                SET state=%s, updated_at=%s, sla_paused_at=%s, sla_paused_seconds=%s
                WHERE case_id=%s
                """,
                (target, now, paused_at, paused_seconds, case_id),
            )
            detail = f"{current} -> {target}"
            if clean_reason:
                detail += f" | reason: {clean_reason}"
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (case_id, actor, "state-transition", detail, now),
            )
        conn.commit()


def add_case_note_pg(
    dsn: str,
    case_id: str,
    *,
    author: str,
    text: str,
    disposition: str | None = None,
) -> int:
    clean = text.strip()
    author = author.strip() or "analyst"
    if not clean:
        raise ValueError("Note text cannot be empty")
    if len(clean) > 5000:
        raise ValueError("Note text must be 5000 characters or fewer")
    if len(author) > 120:
        raise ValueError("Author must be 120 characters or fewer")
    if disposition is not None and len(str(disposition)) > 80:
        raise ValueError("Disposition must be 80 characters or fewer")
    now = datetime.now(timezone.utc)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            _require_case(cur, case_id)
            cur.execute(
                """
                INSERT INTO case_notes(case_id,author,text,disposition,created_at)
                VALUES(%s,%s,%s,%s,%s)
                RETURNING id
                """,
                (case_id, author, clean, disposition, now),
            )
            note_id = int(cur.fetchone()["id"])
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (case_id, author, "note-added", clean[:200], now),
            )
        conn.commit()
    return note_id


def record_case_activity_pg(
    dsn: str,
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
    action = "escalated" if clean_activity == "escalation" else "detection-feedback-recorded"
    now = datetime.now(timezone.utc)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            _require_case(cur, case_id)
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (case_id, clean_actor, action, clean_detail, now),
            )
        conn.commit()


def case_detail_pg(dsn: str, case_id: str) -> dict:
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            case = _require_case(cur, case_id)
            cur.execute(
                "SELECT * FROM case_notes WHERE case_id=%s ORDER BY created_at DESC",
                (case_id,),
            )
            notes = cur.fetchall()
            cur.execute(
                "SELECT * FROM case_audit WHERE case_id=%s ORDER BY timestamp DESC",
                (case_id,),
            )
            audit = cur.fetchall()
            state_history = state_history_from_audit(audit)
            cur.execute(
                """
                SELECT
                  a.*,
                  ca.correlation_score,
                  ca.correlation_reasons,
                  ca.linked_at
                FROM case_alerts ca
                JOIN alerts a ON a.alert_id=ca.alert_id
                WHERE ca.case_id=%s
                ORDER BY a.timestamp ASC
                """,
                (case_id,),
            )
            alerts = cur.fetchall()
            cur.execute(
                """
                SELECT * FROM evidence_collections
                WHERE case_id=%s
                ORDER BY started_at DESC
                """,
                (case_id,),
            )
            collections = cur.fetchall()
            cur.execute(
                """
                SELECT * FROM evidence_requirements
                WHERE case_id=%s
                ORDER BY created_at ASC
                """,
                (case_id,),
            )
            requirements = cur.fetchall()

    case_payload = dict(case)
    for key in ("opened_at", "updated_at", "acknowledged_at", "sla_paused_at"):
        case_payload[key] = _iso(case_payload.get(key))
    for row in notes:
        row["created_at"] = _iso(row.get("created_at"))
    for row in audit:
        row["timestamp"] = _iso(row.get("timestamp"))
    for row in alerts:
        row["alert_id"] = row.get("source_alert_id") or row["alert_id"]
        row["timestamp"] = _iso(row.get("timestamp"))
        row["created_at"] = _iso(row.get("created_at"))
        row["linked_at"] = _iso(row.get("linked_at"))
    for row in collections:
        row["window_start"] = _iso(row.get("window_start"))
        row["window_end"] = _iso(row.get("window_end"))
        row["started_at"] = _iso(row.get("started_at"))
        row["completed_at"] = _iso(row.get("completed_at"))
        row["query"] = row.pop("query_json", {})
    for row in requirements:
        row["due_at"] = _iso(row.get("due_at"))
        row["created_at"] = _iso(row.get("created_at"))
        row["updated_at"] = _iso(row.get("updated_at"))
        row["received_at"] = _iso(row.get("received_at"))
    return {
        "case": case_payload,
        "notes": notes,
        "audit": audit,
        "state_history": state_history,
        "alerts": alerts,
        "evidence_collections": collections,
        "evidence_requirements": requirements,
    }


def list_cases_pg(
    dsn: str,
    *,
    query: str | None = None,
    priority: str | None = None,
    state: str | None = None,
    owner: str | None = None,
) -> list[EnterpriseCase]:
    sql = "SELECT * FROM cases WHERE TRUE"
    params: list[str] = []
    if query:
        sql += " AND (case_id ILIKE %s OR COALESCE(title,'') ILIKE %s OR COALESCE(source,'') ILIKE %s)"
        needle = f"%{query}%"
        params += [needle, needle, needle]
    if priority:
        sql += " AND priority=%s"
        params.append(priority)
    if state:
        sql += " AND state=%s"
        params.append(state)
    if owner:
        if owner == "Unassigned":
            sql += " AND owner IS NULL"
        else:
            sql += " AND owner=%s"
            params.append(owner)
    sql += " ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END, opened_at"

    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    return [_row_to_case(dict(row)) for row in rows]


def command_center_snapshot_pg(
    dsn: str,
    *,
    query: str | None = None,
    priority: str | None = None,
    state: str | None = None,
    owner: str | None = None,
) -> dict:
    all_cases = list_cases_pg(dsn)
    cases = list_cases_pg(
        dsn,
        query=query,
        priority=priority,
        state=state,
        owner=owner,
    )
    active_all = [
        case
        for case in all_cases
        if case.state not in CLOSED_STATES
    ]
    breached = [
        case.case_id
        for case in active_all
        if evaluate_sla(
            case.opened_at,
            priority=case.priority,
            paused_seconds=case.sla_paused_seconds,
            paused_at=case.sla_paused_at,
        ).breached
    ]

    owner_counts: dict[str, int] = {}
    for case in active_all:
        key = case.owner or "Unassigned"
        owner_counts[key] = owner_counts.get(key, 0) + 1

    mtta_values: list[int] = []
    for case in all_cases:
        if case.acknowledged_at:
            opened = datetime.fromisoformat(case.opened_at.replace("Z", "+00:00"))
            ack = datetime.fromisoformat(case.acknowledged_at.replace("Z", "+00:00"))
            mtta_values.append(max(0, int((ack - opened).total_seconds() // 60)))

    resolved = [case for case in all_cases if case.state == "resolved"]
    mttr_values: list[int] = []
    for case in resolved:
        opened = datetime.fromisoformat(case.opened_at.replace("Z", "+00:00"))
        closed = datetime.fromisoformat(case.updated_at.replace("Z", "+00:00"))
        mttr_values.append(max(0, int((closed - opened).total_seconds() // 60)))

    now = datetime.now(timezone.utc)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT case_id,status,due_at
                FROM evidence_requirements
                WHERE status IN ('required','requested')
                """
            )
            requirement_rows = cur.fetchall()
    requirement_counts: dict[str, dict[str, int]] = {}
    for row in requirement_rows:
        bucket = requirement_counts.setdefault(
            str(row["case_id"]),
            {"open": 0, "overdue": 0},
        )
        bucket["open"] += 1
        if row.get("due_at") is not None and row["due_at"] < now:
            bucket["overdue"] += 1

    active_filtered = [
        case
        for case in cases
        if case.state not in CLOSED_STATES
    ]
    sla_by_case = {
        case.case_id: evaluate_sla(
            case.opened_at,
            priority=case.priority,
            paused_seconds=case.sla_paused_seconds,
            paused_at=case.sla_paused_at,
        )
        for case in active_filtered
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(all_cases),
            "active": len(active_all),
            "p1_active": sum(1 for case in active_all if case.priority == "P1"),
            "unassigned": sum(1 for case in active_all if not case.owner),
            "sla_breached": len(breached),
            "sla_paused": sum(1 for case in active_all if case.state in PAUSED_STATES),
            "resolved": len(resolved),
            "mtta_minutes": round(sum(mtta_values) / len(mtta_values), 1)
            if mtta_values
            else None,
            "mttr_minutes": round(sum(mttr_values) / len(mttr_values), 1)
            if mttr_values
            else None,
        },
        "filters": {
            "query": query,
            "priority": priority,
            "state": state,
            "owner": owner,
        },
        "sla_breaches": breached,
        "workload": [
            {"owner": key, "active_cases": count}
            for key, count in sorted(
                owner_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ],
        "queue": [
            {
                "case_id": case.case_id,
                "title": case.title or case.case_id,
                "state": case.state,
                "priority": case.priority,
                "owner": case.owner,
                "source": case.source,
                "opened_at": case.opened_at,
                "updated_at": case.updated_at,
                "acknowledged_at": case.acknowledged_at,
                "has_evidence": bool(case.evidence_path),
                "evidence_requirements": requirement_counts.get(
                    case.case_id,
                    {"open": 0, "overdue": 0},
                ),
                "sla": {
                    "breached": sla_by_case[case.case_id].breached,
                    "remaining_minutes": sla_by_case[case.case_id].remaining_minutes,
                    "paused": sla_by_case[case.case_id].paused,
                    "paused_minutes": sla_by_case[case.case_id].paused_minutes,
                }
                if case.case_id in sla_by_case
                else None,
            }
            for case in cases
        ],
    }
