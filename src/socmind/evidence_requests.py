from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .command_center import connect
from .contradiction import review_hypotheses
from .enterprise_command_center import _connect
from .models import Event


VALID_REQUEST_STATUSES = (
    "pending",
    "in-progress",
    "fulfilled",
    "cancelled",
)


@dataclass(frozen=True, slots=True)
class EvidenceSuggestion:
    key: str
    title: str
    source: str
    target: str | None
    rationale: str


@dataclass(frozen=True, slots=True)
class EvidenceRequest:
    request_id: str
    case_id: str
    key: str
    title: str
    source: str
    target: str | None
    rationale: str
    status: str
    requested_by: str
    assigned_to: str | None
    due_at: str | None
    created_at: str
    updated_at: str
    fulfilled_at: str | None
    response_summary: str | None
    evidence_reference: str | None


def _primary_target(events: list[Event]) -> tuple[str | None, str | None]:
    user = next((event.user for event in events if event.user), None)
    host = next((event.host for event in events if event.host), None)
    return user, host


def suggest_evidence_requests(events: list[Event]) -> list[EvidenceSuggestion]:
    reviews = review_hypotheses(events)
    user, host = _primary_target(events)
    suggestions: dict[str, EvidenceSuggestion] = {}

    def add(key: str, title: str, source: str, target: str | None, rationale: str):
        suggestions.setdefault(
            key,
            EvidenceSuggestion(key, title, source, target, rationale),
        )

    for review in reviews:
        name = review.hypothesis.lower()
        gaps = [*review.validation_gaps, *review.unresolved]

        if "account compromise" in name:
            add(
                "identity-session-context",
                "Collect IdP / MFA session context",
                "identity",
                user,
                "Validate authentication method, MFA result, session and device trust.",
            )
            add(
                "network-access-context",
                "Collect VPN / remote-access session context",
                "network",
                user,
                "Validate whether the source IP and remote-access path are expected for the user.",
            )

        if "malicious execution" in name:
            add(
                "process-ancestry",
                "Collect process ancestry and execution context",
                "endpoint",
                host,
                "Validate parent/child process lineage, signer and command execution context.",
            )
            add(
                "change-control-context",
                "Collect approved change / automation context",
                "change-management",
                host,
                "Determine whether the execution was expected administrative or automation activity.",
            )

        if "persistence" in name:
            add(
                "persistence-owner",
                "Collect persistence creator and change context",
                "endpoint",
                host,
                "Identify the account/process that created the persistence mechanism and validate approval.",
            )

        for gap in gaps:
            low = gap.lower()
            if "mfa" in low or "idp" in low:
                add(
                    "identity-session-context",
                    "Collect IdP / MFA session context",
                    "identity",
                    user,
                    gap,
                )
            if "source ip" in low or "baseline" in low or "vpn" in low:
                add(
                    "network-access-context",
                    "Collect VPN / remote-access session context",
                    "network",
                    user,
                    gap,
                )
            if "process ancestry" in low or "signer" in low:
                add(
                    "process-ancestry",
                    "Collect process ancestry and execution context",
                    "endpoint",
                    host,
                    gap,
                )
            if "change" in low or "approved" in low:
                add(
                    "change-control-context",
                    "Collect approved change / automation context",
                    "change-management",
                    host,
                    gap,
                )

    return sorted(suggestions.values(), key=lambda item: (item.source, item.key))


def suggestion_payload(events: list[Event]) -> dict:
    suggestions = suggest_evidence_requests(events)
    return {
        "count": len(suggestions),
        "suggestions": [asdict(item) for item in suggestions],
    }


def _validate_status(status: str) -> str:
    value = status.strip().lower()
    if value not in VALID_REQUEST_STATUSES:
        raise ValueError(f"Unknown evidence request status: {value}")
    return value


def _due_at(hours: int | None) -> str | None:
    if hours is None:
        return None
    return (
        datetime.now(timezone.utc) + timedelta(hours=max(1, int(hours)))
    ).isoformat()


def create_request_sqlite(
    db_path: str | Path,
    *,
    case_id: str,
    key: str,
    title: str,
    source: str,
    target: str | None,
    rationale: str,
    requested_by: str,
    assigned_to: str | None = None,
    due_hours: int | None = 4,
) -> str:
    now = datetime.now(timezone.utc).isoformat()
    request_id = str(uuid4())
    with connect(db_path) as conn:
        case = conn.execute("SELECT case_id FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if case is None:
            raise ValueError(f"Unknown case: {case_id}")
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO evidence_requests(
              request_id,case_id,key,title,source,target,rationale,status,
              requested_by,assigned_to,due_at,created_at,updated_at,
              fulfilled_at,response_summary,evidence_reference
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                request_id, case_id, key, title, source, target, rationale,
                "pending", requested_by, assigned_to, _due_at(due_hours),
                now, now, None, None, None,
            ),
        )
        if cur.rowcount == 0:
            existing = conn.execute(
                """
                SELECT request_id FROM evidence_requests
                WHERE case_id=? AND key=? AND status IN ('pending','in-progress')
                LIMIT 1
                """,
                (case_id, key),
            ).fetchone()
            if existing is None:
                raise RuntimeError("Evidence request could not be created")
            return existing["request_id"]
        conn.execute(
            """
            INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
            VALUES(?,?,?,?,?)
            """,
            (case_id, requested_by, "evidence-request-created", title, now),
        )
        conn.commit()
    return request_id


def list_requests_sqlite(db_path: str | Path, case_id: str) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM evidence_requests WHERE case_id=? ORDER BY created_at",
            (case_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def update_request_sqlite(
    db_path: str | Path,
    request_id: str,
    *,
    status: str,
    actor: str,
    response_summary: str | None = None,
    evidence_reference: str | None = None,
    assigned_to: str | None = None,
) -> None:
    value = _validate_status(status)
    now = datetime.now(timezone.utc).isoformat()
    fulfilled = now if value == "fulfilled" else None
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM evidence_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"Unknown evidence request: {request_id}")
        conn.execute(
            """
            UPDATE evidence_requests
            SET status=?,
                assigned_to=COALESCE(?,assigned_to),
                updated_at=?,
                fulfilled_at=?,
                response_summary=COALESCE(?,response_summary),
                evidence_reference=COALESCE(?,evidence_reference)
            WHERE request_id=?
            """,
            (
                value, assigned_to, now, fulfilled, response_summary,
                evidence_reference, request_id,
            ),
        )
        conn.execute(
            """
            INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
            VALUES(?,?,?,?,?)
            """,
            (
                row["case_id"],
                actor,
                "evidence-request-updated",
                f"{row['title']} -> {value}",
                now,
            ),
        )
        conn.commit()


def create_request_pg(
    dsn: str,
    *,
    case_id: str,
    key: str,
    title: str,
    source: str,
    target: str | None,
    rationale: str,
    requested_by: str,
    assigned_to: str | None = None,
    due_hours: int | None = 4,
) -> str:
    now = datetime.now(timezone.utc)
    request_id = str(uuid4())
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT case_id FROM cases WHERE case_id=%s", (case_id,))
            if cur.fetchone() is None:
                raise ValueError(f"Unknown case: {case_id}")
            cur.execute(
                """
                INSERT INTO evidence_requests(
                  request_id,case_id,key,title,source,target,rationale,status,
                  requested_by,assigned_to,due_at,created_at,updated_at,
                  fulfilled_at,response_summary,evidence_reference
                ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (
                    request_id, case_id, key, title, source, target, rationale,
                    "pending", requested_by, assigned_to,
                    datetime.fromisoformat(_due_at(due_hours)) if due_hours is not None else None,
                    now, now, None, None, None,
                ),
            )
            if cur.rowcount == 0:
                cur.execute(
                    """
                    SELECT request_id FROM evidence_requests
                    WHERE case_id=%s AND key=%s
                      AND status IN ('pending','in-progress')
                    LIMIT 1
                    """,
                    (case_id, key),
                )
                existing = cur.fetchone()
                if existing is None:
                    raise RuntimeError("Evidence request could not be created")
                return existing["request_id"]
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (case_id, requested_by, "evidence-request-created", title, now),
            )
        conn.commit()
    return request_id


def list_requests_pg(dsn: str, case_id: str) -> list[dict]:
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM evidence_requests WHERE case_id=%s ORDER BY created_at",
                (case_id,),
            )
            rows = cur.fetchall()
    payload = []
    for row in rows:
        item = dict(row)
        for key in ("due_at", "created_at", "updated_at", "fulfilled_at"):
            value = item.get(key)
            if isinstance(value, datetime):
                item[key] = value.isoformat()
        payload.append(item)
    return payload


def update_request_pg(
    dsn: str,
    request_id: str,
    *,
    status: str,
    actor: str,
    response_summary: str | None = None,
    evidence_reference: str | None = None,
    assigned_to: str | None = None,
) -> None:
    value = _validate_status(status)
    now = datetime.now(timezone.utc)
    fulfilled = now if value == "fulfilled" else None
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM evidence_requests WHERE request_id=%s FOR UPDATE",
                (request_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise ValueError(f"Unknown evidence request: {request_id}")
            cur.execute(
                """
                UPDATE evidence_requests
                SET status=%s,
                    assigned_to=COALESCE(%s,assigned_to),
                    updated_at=%s,
                    fulfilled_at=%s,
                    response_summary=COALESCE(%s,response_summary),
                    evidence_reference=COALESCE(%s,evidence_reference)
                WHERE request_id=%s
                """,
                (
                    value, assigned_to, now, fulfilled, response_summary,
                    evidence_reference, request_id,
                ),
            )
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (
                    row["case_id"],
                    actor,
                    "evidence-request-updated",
                    f"{row['title']} -> {value}",
                    now,
                ),
            )
        conn.commit()


def ensure_suggested_requests_sqlite(
    db_path: str | Path,
    *,
    case_id: str,
    events: list[Event],
    requested_by: str,
    assigned_to: str | None = None,
    due_hours: int | None = 4,
) -> list[str]:
    request_ids = []
    for suggestion in suggest_evidence_requests(events):
        request_ids.append(
            create_request_sqlite(
                db_path,
                case_id=case_id,
                key=suggestion.key,
                title=suggestion.title,
                source=suggestion.source,
                target=suggestion.target,
                rationale=suggestion.rationale,
                requested_by=requested_by,
                assigned_to=assigned_to,
                due_hours=due_hours,
            )
        )
    return request_ids


def ensure_suggested_requests_pg(
    dsn: str,
    *,
    case_id: str,
    events: list[Event],
    requested_by: str,
    assigned_to: str | None = None,
    due_hours: int | None = 4,
) -> list[str]:
    request_ids = []
    for suggestion in suggest_evidence_requests(events):
        request_ids.append(
            create_request_pg(
                dsn,
                case_id=case_id,
                key=suggestion.key,
                title=suggestion.title,
                source=suggestion.source,
                target=suggestion.target,
                rationale=suggestion.rationale,
                requested_by=requested_by,
                assigned_to=assigned_to,
                due_hours=due_hours,
            )
        )
    return request_ids
