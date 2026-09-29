from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .command_center import connect
from .contradiction import review_hypotheses
from .enterprise_command_center import _connect
from .models import Event


VALID_REQUIREMENT_STATUSES = (
    "required",
    "requested",
    "received",
    "unavailable",
    "waived",
)

OPEN_REQUIREMENT_STATUSES = {"required", "requested"}

ALLOWED_REQUIREMENT_TRANSITIONS = {
    "required": {"requested", "received", "unavailable", "waived"},
    "requested": {"received", "unavailable", "waived"},
    "unavailable": {"requested", "received", "waived"},
    "received": set(),
    "waived": set(),
}


@dataclass(frozen=True, slots=True)
class EvidenceRequirementSuggestion:
    key: str
    title: str
    source: str
    target: str | None
    rationale: str


def _clean_required(value: str, field: str, *, max_length: int) -> str:
    clean = str(value or "").strip()
    if not clean:
        raise ValueError(f"{field} cannot be empty")
    if len(clean) > max_length:
        raise ValueError(f"{field} must be {max_length} characters or fewer")
    return clean


def _optional_text(value, field: str, *, max_length: int) -> str | None:
    if value is None:
        return None
    clean = str(value).strip()
    if not clean:
        return None
    if len(clean) > max_length:
        raise ValueError(f"{field} must be {max_length} characters or fewer")
    return clean


def _validate_status(status: str) -> str:
    value = str(status or "").strip().lower()
    if value not in VALID_REQUIREMENT_STATUSES:
        raise ValueError(f"Unknown evidence requirement status: {value}")
    return value


def _validate_transition(current: str, target: str) -> str:
    target = _validate_status(target)
    if target == current:
        return target
    if target not in ALLOWED_REQUIREMENT_TRANSITIONS.get(current, set()):
        raise ValueError(
            f"Invalid evidence requirement transition: {current} -> {target}"
        )
    return target


def _due_at(hours: int | None) -> str | None:
    if hours is None:
        return None
    value = int(hours)
    if value < 1 or value > 24 * 30:
        raise ValueError("due_hours must be between 1 and 720")
    return (datetime.now(timezone.utc) + timedelta(hours=value)).isoformat()


def _primary_target(events: list[Event]) -> tuple[str | None, str | None]:
    user = next((event.user for event in events if event.user), None)
    host = next((event.host for event in events if event.host), None)
    return user, host


def suggest_evidence_requirements(
    events: list[Event],
) -> list[EvidenceRequirementSuggestion]:
    """Turn validation gaps/unresolved questions into explicit evidence needs.

    Missing evidence remains a requirement to collect or disposition. It is never
    converted into contradicting evidence by this function.
    """
    reviews = review_hypotheses(events)
    user, host = _primary_target(events)
    suggestions: dict[str, EvidenceRequirementSuggestion] = {}

    def add(
        key: str,
        title: str,
        source: str,
        target: str | None,
        rationale: str,
    ) -> None:
        suggestions.setdefault(
            key,
            EvidenceRequirementSuggestion(
                key=key,
                title=title,
                source=source,
                target=target,
                rationale=rationale,
            ),
        )

    for review in reviews:
        name = review.hypothesis.lower()
        gaps = [*review.validation_gaps, *review.unresolved]

        if "account compromise" in name:
            add(
                "identity-session-context",
                "Collect IdP authentication and MFA context",
                "identity",
                user,
                "Validate authentication method, MFA result, session, device trust, and identity-provider context.",
            )
            add(
                "network-access-context",
                "Collect VPN and remote-access history",
                "network",
                user,
                "Validate source IP, VPN/remote-access path, device history, and expected user baseline.",
            )

        if "malicious execution" in name:
            add(
                "process-ancestry",
                "Collect parent process and execution context",
                "endpoint",
                host,
                "Validate parent/child process lineage, executable signer, command line, and execution origin.",
            )
            add(
                "change-control-context",
                "Collect approved change or automation context",
                "change-management",
                host,
                "Determine whether observed execution was expected administrative or approved automation activity.",
            )

        if "persistence" in name:
            add(
                "persistence-owner",
                "Collect persistence creator and approval context",
                "endpoint",
                host,
                "Identify the account/process that created the persistence mechanism and validate change approval.",
            )

        for gap in gaps:
            low = gap.lower()
            if "mfa" in low or "idp" in low or "authentication" in low:
                add(
                    "identity-session-context",
                    "Collect IdP authentication and MFA context",
                    "identity",
                    user,
                    gap,
                )
            if (
                "source ip" in low
                or "baseline" in low
                or "vpn" in low
                or "remote" in low
            ):
                add(
                    "network-access-context",
                    "Collect VPN and remote-access history",
                    "network",
                    user,
                    gap,
                )
            if (
                "process ancestry" in low
                or "parent process" in low
                or "signer" in low
            ):
                add(
                    "process-ancestry",
                    "Collect parent process and execution context",
                    "endpoint",
                    host,
                    gap,
                )
            if "host scope" in low or "endpoint scope" in low:
                add(
                    "host-scope",
                    "Collect host scope and neighboring endpoint context",
                    "endpoint",
                    host,
                    gap,
                )
            if "change" in low or "approved" in low or "automation" in low:
                add(
                    "change-control-context",
                    "Collect approved change or automation context",
                    "change-management",
                    host,
                    gap,
                )

    return sorted(
        suggestions.values(),
        key=lambda item: (item.source, item.key),
    )


def suggestion_payload(events: list[Event]) -> dict:
    suggestions = suggest_evidence_requirements(events)
    return {
        "count": len(suggestions),
        "suggestions": [asdict(item) for item in suggestions],
    }


def create_requirement_sqlite(
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
    clean_key = _clean_required(key, "key", max_length=120)
    clean_title = _clean_required(title, "title", max_length=240)
    clean_source = _clean_required(source, "source", max_length=120)
    clean_rationale = _clean_required(rationale, "rationale", max_length=2000)
    clean_actor = _clean_required(requested_by, "requested_by", max_length=120)
    clean_target = _optional_text(target, "target", max_length=240)
    clean_assignee = _optional_text(assigned_to, "assigned_to", max_length=120)
    due_at = _due_at(due_hours)
    now = datetime.now(timezone.utc).isoformat()
    requirement_id = str(uuid4())

    with connect(db_path) as conn:
        case = conn.execute(
            "SELECT case_id FROM cases WHERE case_id=?",
            (case_id,),
        ).fetchone()
        if case is None:
            raise ValueError(f"Unknown case: {case_id}")

        cur = conn.execute(
            """
            INSERT OR IGNORE INTO evidence_requirements(
              requirement_id,case_id,key,title,source,target,rationale,status,
              requested_by,assigned_to,due_at,created_at,updated_at,
              received_at,response_summary,evidence_reference
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                requirement_id,
                case_id,
                clean_key,
                clean_title,
                clean_source,
                clean_target,
                clean_rationale,
                "required",
                clean_actor,
                clean_assignee,
                due_at,
                now,
                now,
                None,
                None,
                None,
            ),
        )
        if cur.rowcount == 0:
            existing = conn.execute(
                """
                SELECT requirement_id
                FROM evidence_requirements
                WHERE case_id=? AND key=?
                  AND status IN ('required','requested')
                LIMIT 1
                """,
                (case_id, clean_key),
            ).fetchone()
            if existing is None:
                raise RuntimeError("Evidence requirement could not be created")
            return str(existing["requirement_id"])

        conn.execute(
            """
            INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
            VALUES(?,?,?,?,?)
            """,
            (
                case_id,
                clean_actor,
                "evidence-requirement-created",
                clean_title,
                now,
            ),
        )
        conn.commit()
    return requirement_id


def list_requirements_sqlite(
    db_path: str | Path,
    case_id: str,
) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM evidence_requirements
            WHERE case_id=?
            ORDER BY created_at, requirement_id
            """,
            (case_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def update_requirement_sqlite(
    db_path: str | Path,
    requirement_id: str,
    *,
    status: str,
    actor: str,
    response_summary: str | None = None,
    evidence_reference: str | None = None,
    assigned_to: str | None = None,
) -> str:
    clean_actor = _clean_required(actor, "actor", max_length=120)
    clean_summary = _optional_text(
        response_summary,
        "response_summary",
        max_length=4000,
    )
    clean_reference = _optional_text(
        evidence_reference,
        "evidence_reference",
        max_length=2000,
    )
    clean_assignee = _optional_text(
        assigned_to,
        "assigned_to",
        max_length=120,
    )
    now = datetime.now(timezone.utc).isoformat()

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM evidence_requirements WHERE requirement_id=?",
            (requirement_id,),
        ).fetchone()
        if row is None:
            raise ValueError(
                f"Unknown evidence requirement: {requirement_id}"
            )

        current = str(row["status"])
        target = _validate_transition(current, status)
        if target == current:
            conn.commit()
            return str(row["case_id"])

        if target == "received" and not clean_reference:
            raise ValueError(
                "evidence_reference is required when marking evidence received"
            )
        if target in {"unavailable", "waived"} and not clean_summary:
            raise ValueError(
                "response_summary is required for unavailable or waived evidence"
            )

        received_at = now if target == "received" else row["received_at"]
        conn.execute(
            """
            UPDATE evidence_requirements
            SET status=?,
                assigned_to=COALESCE(?,assigned_to),
                updated_at=?,
                received_at=?,
                response_summary=COALESCE(?,response_summary),
                evidence_reference=COALESCE(?,evidence_reference)
            WHERE requirement_id=?
            """,
            (
                target,
                clean_assignee,
                now,
                received_at,
                clean_summary,
                clean_reference,
                requirement_id,
            ),
        )
        conn.execute(
            """
            INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
            VALUES(?,?,?,?,?)
            """,
            (
                row["case_id"],
                clean_actor,
                "evidence-requirement-updated",
                f"{row['title']}: {current} -> {target}",
                now,
            ),
        )
        conn.commit()
        return str(row["case_id"])


def create_requirement_pg(
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
    clean_key = _clean_required(key, "key", max_length=120)
    clean_title = _clean_required(title, "title", max_length=240)
    clean_source = _clean_required(source, "source", max_length=120)
    clean_rationale = _clean_required(rationale, "rationale", max_length=2000)
    clean_actor = _clean_required(requested_by, "requested_by", max_length=120)
    clean_target = _optional_text(target, "target", max_length=240)
    clean_assignee = _optional_text(assigned_to, "assigned_to", max_length=120)
    due_at_raw = _due_at(due_hours)
    due_at = datetime.fromisoformat(due_at_raw) if due_at_raw else None
    now = datetime.now(timezone.utc)
    requirement_id = str(uuid4())

    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT case_id FROM cases WHERE case_id=%s",
                (case_id,),
            )
            if cur.fetchone() is None:
                raise ValueError(f"Unknown case: {case_id}")

            cur.execute(
                """
                INSERT INTO evidence_requirements(
                  requirement_id,case_id,key,title,source,target,rationale,status,
                  requested_by,assigned_to,due_at,created_at,updated_at,
                  received_at,response_summary,evidence_reference
                ) VALUES(
                  %s,%s,%s,%s,%s,%s,%s,%s,
                  %s,%s,%s,%s,%s,%s,%s,%s
                )
                ON CONFLICT DO NOTHING
                """,
                (
                    requirement_id,
                    case_id,
                    clean_key,
                    clean_title,
                    clean_source,
                    clean_target,
                    clean_rationale,
                    "required",
                    clean_actor,
                    clean_assignee,
                    due_at,
                    now,
                    now,
                    None,
                    None,
                    None,
                ),
            )
            if cur.rowcount == 0:
                cur.execute(
                    """
                    SELECT requirement_id
                    FROM evidence_requirements
                    WHERE case_id=%s AND key=%s
                      AND status IN ('required','requested')
                    LIMIT 1
                    """,
                    (case_id, clean_key),
                )
                existing = cur.fetchone()
                if existing is None:
                    raise RuntimeError("Evidence requirement could not be created")
                return str(existing["requirement_id"])

            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (
                    case_id,
                    clean_actor,
                    "evidence-requirement-created",
                    clean_title,
                    now,
                ),
            )
        conn.commit()
    return requirement_id


def list_requirements_pg(dsn: str, case_id: str) -> list[dict]:
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM evidence_requirements
                WHERE case_id=%s
                ORDER BY created_at, requirement_id
                """,
                (case_id,),
            )
            rows = cur.fetchall()

    payload: list[dict] = []
    for row in rows:
        item = dict(row)
        for key in ("due_at", "created_at", "updated_at", "received_at"):
            value = item.get(key)
            if isinstance(value, datetime):
                item[key] = value.isoformat()
        payload.append(item)
    return payload


def update_requirement_pg(
    dsn: str,
    requirement_id: str,
    *,
    status: str,
    actor: str,
    response_summary: str | None = None,
    evidence_reference: str | None = None,
    assigned_to: str | None = None,
) -> str:
    clean_actor = _clean_required(actor, "actor", max_length=120)
    clean_summary = _optional_text(
        response_summary,
        "response_summary",
        max_length=4000,
    )
    clean_reference = _optional_text(
        evidence_reference,
        "evidence_reference",
        max_length=2000,
    )
    clean_assignee = _optional_text(
        assigned_to,
        "assigned_to",
        max_length=120,
    )
    now = datetime.now(timezone.utc)

    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM evidence_requirements
                WHERE requirement_id=%s
                FOR UPDATE
                """,
                (requirement_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise ValueError(
                    f"Unknown evidence requirement: {requirement_id}"
                )

            current = str(row["status"])
            target = _validate_transition(current, status)
            if target == current:
                return str(row["case_id"])

            if target == "received" and not clean_reference:
                raise ValueError(
                    "evidence_reference is required when marking evidence received"
                )
            if target in {"unavailable", "waived"} and not clean_summary:
                raise ValueError(
                    "response_summary is required for unavailable or waived evidence"
                )

            received_at = now if target == "received" else row.get("received_at")
            cur.execute(
                """
                UPDATE evidence_requirements
                SET status=%s,
                    assigned_to=COALESCE(%s,assigned_to),
                    updated_at=%s,
                    received_at=%s,
                    response_summary=COALESCE(%s,response_summary),
                    evidence_reference=COALESCE(%s,evidence_reference)
                WHERE requirement_id=%s
                """,
                (
                    target,
                    clean_assignee,
                    now,
                    received_at,
                    clean_summary,
                    clean_reference,
                    requirement_id,
                ),
            )
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (
                    row["case_id"],
                    clean_actor,
                    "evidence-requirement-updated",
                    f"{row['title']}: {current} -> {target}",
                    now,
                ),
            )
        conn.commit()
        return str(row["case_id"])


def ensure_suggested_requirements_sqlite(
    db_path: str | Path,
    *,
    case_id: str,
    events: list[Event],
    requested_by: str,
    assigned_to: str | None = None,
    due_hours: int | None = 4,
) -> list[str]:
    return [
        create_requirement_sqlite(
            db_path,
            case_id=case_id,
            key=item.key,
            title=item.title,
            source=item.source,
            target=item.target,
            rationale=item.rationale,
            requested_by=requested_by,
            assigned_to=assigned_to,
            due_hours=due_hours,
        )
        for item in suggest_evidence_requirements(events)
    ]


def ensure_suggested_requirements_pg(
    dsn: str,
    *,
    case_id: str,
    events: list[Event],
    requested_by: str,
    assigned_to: str | None = None,
    due_hours: int | None = 4,
) -> list[str]:
    return [
        create_requirement_pg(
            dsn,
            case_id=case_id,
            key=item.key,
            title=item.title,
            source=item.source,
            target=item.target,
            rationale=item.rationale,
            requested_by=requested_by,
            assigned_to=assigned_to,
            due_hours=due_hours,
        )
        for item in suggest_evidence_requirements(events)
    ]
