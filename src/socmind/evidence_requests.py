from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .case_workflow import ALLOWED
from .command_center import connect
from .enterprise_command_center import _connect
from .postgres_store import initialize_postgres


VALID_STATUSES = {"open", "in-progress", "fulfilled", "cancelled"}
VALID_PRIORITIES = {"normal", "high", "urgent"}


@dataclass(frozen=True, slots=True)
class EvidenceRequest:
    request_id: str
    case_id: str
    kind: str
    description: str
    requested_by: str
    owner: str | None
    priority: str
    status: str
    due_at: str | None
    resolution_note: str | None
    created_at: str
    updated_at: str
    completed_at: str | None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _validate(
    kind: str,
    description: str,
    priority: str,
    due_at: str | None,
) -> tuple[str, str, str, str | None]:
    kind = kind.strip()
    description = description.strip()
    priority = priority.strip().lower()
    if not kind or len(kind) > 80:
        raise ValueError("Evidence request kind is required and must be <= 80 characters")
    if not description or len(description) > 2000:
        raise ValueError("Evidence request description is required and must be <= 2000 characters")
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Unknown evidence request priority: {priority}")
    if due_at:
        parsed = datetime.fromisoformat(str(due_at).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        due_at = parsed.astimezone(timezone.utc).isoformat()
    return kind, description, priority, due_at


def _request_from_mapping(row: dict) -> EvidenceRequest:
    return EvidenceRequest(
        request_id=row["request_id"],
        case_id=row["case_id"],
        kind=row["kind"],
        description=row["description"],
        requested_by=row["requested_by"],
        owner=row.get("owner"),
        priority=row["priority"],
        status=row["status"],
        due_at=_iso(row.get("due_at")),
        resolution_note=row.get("resolution_note"),
        created_at=_iso(row["created_at"]) or "",
        updated_at=_iso(row["updated_at"]) or "",
        completed_at=_iso(row.get("completed_at")),
    )


def create_evidence_request_sqlite(
    db_path: str | Path,
    case_id: str,
    *,
    kind: str,
    description: str,
    requested_by: str,
    owner: str | None = None,
    priority: str = "normal",
    due_at: str | None = None,
) -> EvidenceRequest:
    kind, description, priority, due_at = _validate(kind, description, priority, due_at)
    now = _utc_now().isoformat()
    request_id = f"ER-{uuid.uuid4().hex[:12].upper()}"
    actor = requested_by.strip() or "analyst"

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        case = conn.execute("SELECT state FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if case is None:
            raise ValueError(f"Unknown case: {case_id}")
        conn.execute(
            """
            INSERT INTO evidence_requests(
              request_id,case_id,kind,description,requested_by,owner,priority,status,
              due_at,resolution_note,created_at,updated_at,completed_at
            ) VALUES(?,?,?,?,?,?,?,'open',?,NULL,?,?,NULL)
            """,
            (request_id, case_id, kind, description, actor, owner, priority, due_at, now, now),
        )
        current = case["state"]
        if current in {"triage", "investigating"} and "waiting-for-evidence" in ALLOWED[current]:
            conn.execute(
                "UPDATE cases SET state='waiting-for-evidence', updated_at=? WHERE case_id=?",
                (now, case_id),
            )
        conn.execute(
            "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(?,?,?,?,?)",
            (
                case_id,
                actor,
                "evidence-request-created",
                json.dumps({"request_id": request_id, "kind": kind, "priority": priority, "due_at": due_at}),
                now,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM evidence_requests WHERE request_id=?", (request_id,)).fetchone()
    return _request_from_mapping(dict(row))


def update_evidence_request_sqlite(
    db_path: str | Path,
    request_id: str,
    *,
    actor: str,
    status: str,
    owner: str | None = None,
    resolution_note: str | None = None,
) -> EvidenceRequest:
    status = status.strip().lower()
    if status not in VALID_STATUSES:
        raise ValueError(f"Unknown evidence request status: {status}")
    now = _utc_now().isoformat()
    completed_at = now if status in {"fulfilled", "cancelled"} else None

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM evidence_requests WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown evidence request: {request_id}")
        case_id = row["case_id"]
        conn.execute(
            """
            UPDATE evidence_requests
            SET status=?, owner=COALESCE(?,owner), resolution_note=?, updated_at=?, completed_at=?
            WHERE request_id=?
            """,
            (status, owner, resolution_note, now, completed_at, request_id),
        )
        open_count = conn.execute(
            "SELECT COUNT(*) FROM evidence_requests WHERE case_id=? AND status IN ('open','in-progress')",
            (case_id,),
        ).fetchone()[0]
        case = conn.execute("SELECT state FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if open_count == 0 and case and case["state"] == "waiting-for-evidence":
            conn.execute(
                "UPDATE cases SET state='investigating', updated_at=? WHERE case_id=?",
                (now, case_id),
            )
        conn.execute(
            "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(?,?,?,?,?)",
            (
                case_id,
                actor.strip() or "analyst",
                "evidence-request-updated",
                json.dumps({"request_id": request_id, "status": status, "owner": owner}),
                now,
            ),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM evidence_requests WHERE request_id=?", (request_id,)).fetchone()
    return _request_from_mapping(dict(updated))


def list_evidence_requests_sqlite(db_path: str | Path, case_id: str) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM evidence_requests WHERE case_id=? ORDER BY created_at DESC",
            (case_id,),
        ).fetchall()
    return [asdict(_request_from_mapping(dict(row))) for row in rows]


def create_evidence_request_postgres(
    dsn: str,
    case_id: str,
    *,
    kind: str,
    description: str,
    requested_by: str,
    owner: str | None = None,
    priority: str = "normal",
    due_at: str | None = None,
) -> EvidenceRequest:
    initialize_postgres(dsn)
    kind, description, priority, due_at = _validate(kind, description, priority, due_at)
    now = _utc_now()
    request_id = f"ER-{uuid.uuid4().hex[:12].upper()}"
    actor = requested_by.strip() or "analyst"

    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT state FROM cases WHERE case_id=%s FOR UPDATE", (case_id,))
            case = cur.fetchone()
            if case is None:
                raise ValueError(f"Unknown case: {case_id}")
            cur.execute(
                """
                INSERT INTO evidence_requests(
                  request_id,case_id,kind,description,requested_by,owner,priority,status,
                  due_at,resolution_note,created_at,updated_at,completed_at
                ) VALUES(%s,%s,%s,%s,%s,%s,%s,'open',%s,NULL,%s,%s,NULL)
                """,
                (request_id, case_id, kind, description, actor, owner, priority, due_at, now, now),
            )
            current = case["state"]
            if current in {"triage", "investigating"} and "waiting-for-evidence" in ALLOWED[current]:
                cur.execute(
                    "UPDATE cases SET state='waiting-for-evidence', updated_at=%s WHERE case_id=%s",
                    (now, case_id),
                )
            cur.execute(
                "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(%s,%s,%s,%s,%s)",
                (
                    case_id,
                    actor,
                    "evidence-request-created",
                    json.dumps({"request_id": request_id, "kind": kind, "priority": priority, "due_at": due_at}),
                    now,
                ),
            )
            cur.execute("SELECT * FROM evidence_requests WHERE request_id=%s", (request_id,))
            row = cur.fetchone()
        conn.commit()
    return _request_from_mapping(dict(row))


def update_evidence_request_postgres(
    dsn: str,
    request_id: str,
    *,
    actor: str,
    status: str,
    owner: str | None = None,
    resolution_note: str | None = None,
) -> EvidenceRequest:
    initialize_postgres(dsn)
    status = status.strip().lower()
    if status not in VALID_STATUSES:
        raise ValueError(f"Unknown evidence request status: {status}")
    now = _utc_now()
    completed_at = now if status in {"fulfilled", "cancelled"} else None

    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM evidence_requests WHERE request_id=%s FOR UPDATE", (request_id,))
            row = cur.fetchone()
            if row is None:
                raise ValueError(f"Unknown evidence request: {request_id}")
            case_id = row["case_id"]
            cur.execute(
                """
                UPDATE evidence_requests
                SET status=%s, owner=COALESCE(%s,owner), resolution_note=%s,
                    updated_at=%s, completed_at=%s
                WHERE request_id=%s
                """,
                (status, owner, resolution_note, now, completed_at, request_id),
            )
            cur.execute(
                "SELECT COUNT(*) AS count FROM evidence_requests WHERE case_id=%s AND status IN ('open','in-progress')",
                (case_id,),
            )
            open_count = int(cur.fetchone()["count"])
            cur.execute("SELECT state FROM cases WHERE case_id=%s FOR UPDATE", (case_id,))
            case = cur.fetchone()
            if open_count == 0 and case and case["state"] == "waiting-for-evidence":
                cur.execute(
                    "UPDATE cases SET state='investigating', updated_at=%s WHERE case_id=%s",
                    (now, case_id),
                )
            cur.execute(
                "INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(%s,%s,%s,%s,%s)",
                (
                    case_id,
                    actor.strip() or "analyst",
                    "evidence-request-updated",
                    json.dumps({"request_id": request_id, "status": status, "owner": owner}),
                    now,
                ),
            )
            cur.execute("SELECT * FROM evidence_requests WHERE request_id=%s", (request_id,))
            updated = cur.fetchone()
        conn.commit()
    return _request_from_mapping(dict(updated))


def list_evidence_requests_postgres(dsn: str, case_id: str) -> list[dict]:
    initialize_postgres(dsn)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM evidence_requests WHERE case_id=%s ORDER BY created_at DESC",
                (case_id,),
            )
            rows = cur.fetchall()
    return [asdict(_request_from_mapping(dict(row))) for row in rows]
