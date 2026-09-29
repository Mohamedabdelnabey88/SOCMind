from pathlib import Path

from socmind.case_workflow import new_case, transition
from socmind.command_center import command_center_snapshot, upsert_case
from socmind.evidence_requests import (
    create_request_sqlite,
    ensure_suggested_requests_sqlite,
    list_requests_sqlite,
    suggest_evidence_requests,
    update_request_sqlite,
)
from socmind.io import load_jsonl


ROOT = Path(__file__).resolve().parents[1]


def test_advanced_case_lifecycle_supports_waiting_states():
    case = new_case("INC-LIFE", priority="P2")
    transition(case, "triage")
    transition(case, "investigating")
    transition(case, "waiting-for-evidence")
    transition(case, "investigating")
    transition(case, "contained")
    transition(case, "monitoring")
    transition(case, "resolved")
    assert case.state == "resolved"


def test_validation_gaps_generate_actionable_evidence_suggestions():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    suggestions = suggest_evidence_requests(events)
    assert suggestions
    keys = {item.key for item in suggestions}
    assert "identity-session-context" in keys
    assert "process-ancestry" in keys
    assert all(item.source for item in suggestions)
    assert all(item.rationale for item in suggestions)


def test_sqlite_evidence_request_lifecycle(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(db, new_case("INC-EVIDENCE", priority="P1"))

    request_id = create_request_sqlite(
        db,
        case_id="INC-EVIDENCE",
        key="identity-session-context",
        title="Collect IdP / MFA session context",
        source="identity",
        target="alice",
        rationale="Validate MFA and device trust.",
        requested_by="tier2",
        assigned_to="identity-team",
        due_hours=2,
    )
    rows = list_requests_sqlite(db, "INC-EVIDENCE")
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert rows[0]["assigned_to"] == "identity-team"
    assert rows[0]["due_at"]

    update_request_sqlite(
        db,
        request_id,
        status="fulfilled",
        actor="identity-team",
        response_summary="MFA passed from managed device.",
        evidence_reference="idp://session/123",
    )
    row = list_requests_sqlite(db, "INC-EVIDENCE")[0]
    assert row["status"] == "fulfilled"
    assert row["fulfilled_at"]
    assert row["evidence_reference"] == "idp://session/123"


def test_suggested_requests_are_idempotent_and_visible_in_queue(tmp_path):
    db = tmp_path / "soc.db"
    events_path = ROOT / "examples/attack_chain.jsonl"
    events = load_jsonl(events_path)
    upsert_case(
        db,
        new_case("INC-SUGGEST", priority="P1"),
        evidence_path=events_path,
    )

    first = ensure_suggested_requests_sqlite(
        db,
        case_id="INC-SUGGEST",
        events=events,
        requested_by="tier2",
        due_hours=4,
    )
    second = ensure_suggested_requests_sqlite(
        db,
        case_id="INC-SUGGEST",
        events=events,
        requested_by="tier2",
        due_hours=4,
    )
    assert first == second
    rows = list_requests_sqlite(db, "INC-SUGGEST")
    assert len(rows) == len(set(first))

    snapshot = command_center_snapshot(db)
    queued = next(item for item in snapshot["queue"] if item["case_id"] == "INC-SUGGEST")
    assert queued["evidence_requests"]["open"] == len(rows)
    assert snapshot["summary"]["open_evidence_requests"] == len(rows)


def test_evidence_request_terminal_states_cannot_reopen(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(db, new_case("INC-TERMINAL", priority="P2"))
    request_id = create_request_sqlite(
        db,
        case_id="INC-TERMINAL",
        key="process-ancestry",
        title="Collect process ancestry",
        source="endpoint",
        target="host-1",
        rationale="Validate execution lineage.",
        requested_by="tier2",
    )
    update_request_sqlite(
        db,
        request_id,
        status="fulfilled",
        actor="tier2",
        response_summary="Collected.",
    )

    import pytest
    with pytest.raises(ValueError, match="Invalid evidence request transition"):
        update_request_sqlite(
            db,
            request_id,
            status="in-progress",
            actor="tier2",
        )
