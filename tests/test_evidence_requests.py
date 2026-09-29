from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from socmind.case_workflow import new_case
from socmind.command_center import command_center_snapshot, connect, upsert_case
from socmind.evidence_requests import (
    create_requirement_sqlite,
    ensure_suggested_requirements_sqlite,
    list_requirements_sqlite,
    suggest_evidence_requirements,
    update_requirement_sqlite,
)
from socmind.io import load_jsonl


ROOT = Path(__file__).resolve().parents[1]


def _create_case(db, case_id="REQ-001"):
    upsert_case(
        db,
        new_case(case_id, priority="P2"),
        source="elastic",
        title="Evidence requirement case",
        evidence_path=ROOT / "examples/attack_chain.jsonl",
    )


def test_validation_gaps_become_explicit_evidence_requirements():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    suggestions = suggest_evidence_requirements(events)
    keys = {item.key for item in suggestions}

    assert suggestions
    assert "identity-session-context" in keys
    assert "network-access-context" in keys
    assert "process-ancestry" in keys
    assert all(item.rationale.strip() for item in suggestions)


def test_sqlite_requirement_lifecycle_and_idempotency(tmp_path):
    db = tmp_path / "soc.db"
    _create_case(db)

    first = create_requirement_sqlite(
        db,
        case_id="REQ-001",
        key="mfa-context",
        title="Collect MFA context",
        source="identity",
        target="alice",
        rationale="MFA result is missing",
        requested_by="tier1",
        due_hours=4,
    )
    duplicate = create_requirement_sqlite(
        db,
        case_id="REQ-001",
        key="mfa-context",
        title="Collect MFA context",
        source="identity",
        target="alice",
        rationale="MFA result is missing",
        requested_by="tier1",
        due_hours=4,
    )
    assert duplicate == first

    rows = list_requirements_sqlite(db, "REQ-001")
    assert len(rows) == 1
    assert rows[0]["status"] == "required"

    update_requirement_sqlite(
        db,
        first,
        status="requested",
        actor="tier1",
        assigned_to="identity-team",
    )
    requested = list_requirements_sqlite(db, "REQ-001")[0]
    assert requested["status"] == "requested"
    assert requested["assigned_to"] == "identity-team"

    with pytest.raises(ValueError, match="evidence_reference is required"):
        update_requirement_sqlite(
            db,
            first,
            status="received",
            actor="tier2",
        )

    update_requirement_sqlite(
        db,
        first,
        status="received",
        actor="tier2",
        response_summary="MFA challenge succeeded from managed device",
        evidence_reference="case://REQ-001/idp/mfa-001",
    )
    received = list_requirements_sqlite(db, "REQ-001")[0]
    assert received["status"] == "received"
    assert received["received_at"]
    assert received["evidence_reference"] == "case://REQ-001/idp/mfa-001"

    with pytest.raises(ValueError, match="Invalid evidence requirement transition"):
        update_requirement_sqlite(
            db,
            first,
            status="requested",
            actor="tier2",
        )


def test_unavailable_and_waived_require_documented_reason(tmp_path):
    db = tmp_path / "soc.db"
    _create_case(db)

    unavailable_id = create_requirement_sqlite(
        db,
        case_id="REQ-001",
        key="vpn-history",
        title="Collect VPN history",
        source="network",
        target="alice",
        rationale="VPN context missing",
        requested_by="tier1",
    )
    with pytest.raises(ValueError, match="response_summary is required"):
        update_requirement_sqlite(
            db,
            unavailable_id,
            status="unavailable",
            actor="tier2",
        )
    update_requirement_sqlite(
        db,
        unavailable_id,
        status="unavailable",
        actor="tier2",
        response_summary="VPN retention expired before incident window",
    )

    waived_id = create_requirement_sqlite(
        db,
        case_id="REQ-001",
        key="host-scope",
        title="Collect host scope",
        source="endpoint",
        target="host-01",
        rationale="Scope validation requested",
        requested_by="tier1",
    )
    with pytest.raises(ValueError, match="response_summary is required"):
        update_requirement_sqlite(
            db,
            waived_id,
            status="waived",
            actor="lead",
        )
    update_requirement_sqlite(
        db,
        waived_id,
        status="waived",
        actor="lead",
        response_summary="Lead accepted scope risk after documented review",
    )

    statuses = {row["key"]: row["status"] for row in list_requirements_sqlite(db, "REQ-001")}
    assert statuses["vpn-history"] == "unavailable"
    assert statuses["host-scope"] == "waived"


def test_concurrent_requirement_creation_collapses_to_one_open_requirement(tmp_path):
    db = tmp_path / "soc.db"
    _create_case(db)

    def create():
        return create_requirement_sqlite(
            db,
            case_id="REQ-001",
            key="process-ancestry",
            title="Collect process ancestry",
            source="endpoint",
            target="host-01",
            rationale="Parent process is missing",
            requested_by="tier1",
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(lambda _: create(), range(4)))

    assert len(set(ids)) == 1
    rows = list_requirements_sqlite(db, "REQ-001")
    assert len(rows) == 1


def test_generated_requirements_are_idempotent_and_visible_in_case_queue(tmp_path):
    db = tmp_path / "soc.db"
    _create_case(db)
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")

    first = ensure_suggested_requirements_sqlite(
        db,
        case_id="REQ-001",
        events=events,
        requested_by="tier1",
    )
    second = ensure_suggested_requirements_sqlite(
        db,
        case_id="REQ-001",
        events=events,
        requested_by="tier1",
    )
    assert first == second

    with connect(db) as conn:
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        conn.execute(
            """
            UPDATE evidence_requirements
            SET due_at=?
            WHERE case_id=? AND status='required'
            """,
            (past, "REQ-001"),
        )
        conn.commit()

    snapshot = command_center_snapshot(db)
    item = next(row for row in snapshot["queue"] if row["case_id"] == "REQ-001")
    assert item["evidence_requirements"]["open"] == len(first)
    assert item["evidence_requirements"]["overdue"] == len(first)
