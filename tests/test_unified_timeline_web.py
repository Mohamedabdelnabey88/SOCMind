from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import (
    acknowledge_case,
    add_case_note,
    assign_case,
    transition_case,
    upsert_case,
)
from socmind.enterprise_auth import trusted_proxy_headers
from socmind.io import load_jsonl
from socmind.orchestration import orchestrate_alert_sqlite
from socmind.production_ops import AlertRecord
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def _headers(secret: str, subject: str, role: str):
    return trusted_proxy_headers(secret, subject, role)


def test_unified_timeline_api_includes_operational_case_actions(tmp_path):
    db = tmp_path / "soc.db"
    events_path = ROOT / "examples/attack_chain.jsonl"
    events = load_jsonl(events_path)
    base = events[0]

    root_alert = AlertRecord(
        "TL-WEB-001",
        "elastic",
        base.timestamp,
        "Timeline root alert",
        8,
        base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="TL-ROOT",
    )
    root = orchestrate_alert_sqlite(
        db,
        root_alert,
        events,
        evidence_dir=tmp_path / "evidence",
    )
    follow = AlertRecord(
        "TL-WEB-002",
        "elastic",
        base.timestamp + timedelta(minutes=2),
        "Timeline correlated alert",
        13,
        base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="TL-FOLLOW",
    )
    orchestrate_alert_sqlite(
        db,
        follow,
        events,
        evidence_dir=tmp_path / "evidence",
    )

    acknowledge_case(db, root.case_id, actor="tier1")
    assign_case(db, root.case_id, "tier2", actor="lead")
    transition_case(
        db,
        root.case_id,
        "triage",
        actor="tier2",
        reason="Initial triage completed",
    )
    transition_case(
        db,
        root.case_id,
        "investigating",
        actor="tier2",
        reason="Scope requires deeper validation",
    )
    add_case_note(
        db,
        root.case_id,
        author="tier2",
        text="Validated identity and endpoint context",
    )

    app = create_app(
        events_path,
        case_id=root.case_id,
        command_db=db,
        rules_dir=ROOT / "detections",
    )
    client = TestClient(app)

    escalation = client.post(
        f"/api/cases/{root.case_id}/activities",
        json={
            "type": "escalation",
            "detail": "Escalated to IR for privileged-account impact",
        },
    )
    assert escalation.status_code == 200

    feedback = client.post(
        f"/api/cases/{root.case_id}/activities",
        json={
            "type": "detection-feedback",
            "detail": "Add regression coverage for correlated authentication chain",
        },
    )
    assert feedback.status_code == 200

    response = client.get(f"/api/cases/{root.case_id}/timeline")
    assert response.status_code == 200
    timeline = response.json()["timeline"]
    assert timeline

    required = {"timestamp", "type", "source", "actor", "detail"}
    assert all(required <= set(item) for item in timeline)

    types = {item["type"] for item in timeline}
    assert "alert-received" in types
    assert "case-created" in types
    assert "alert-correlated" in types
    assert "analyst-acknowledged" in types
    assert "assignment" in types
    assert "state-transition" in types
    assert "note" in types
    assert "evidence-event" in types
    assert "detection-event" in types
    assert "escalation" in types
    assert "detection-feedback" in types


def test_case_activity_rbac_separates_escalation_and_detection_feedback(tmp_path):
    db = tmp_path / "soc.db"
    case_id = "TL-RBAC-001"
    upsert_case(
        db,
        new_case(case_id, priority="P2"),
        source="manual",
        title="Timeline RBAC",
        evidence_path=ROOT / "examples/attack_chain.jsonl",
    )

    secret = "timeline-rbac-secret"
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        case_id=case_id,
        command_db=db,
        rules_dir=ROOT / "detections",
        auth_mode="trusted-proxy",
        trusted_proxy_secret=secret,
    )
    client = TestClient(app)

    analyst = _headers(secret, "analyst@example.com", "analyst")
    senior = _headers(secret, "senior@example.com", "senior-analyst")
    viewer = _headers(secret, "viewer@example.com", "viewer")

    denied_escalation = client.post(
        f"/api/cases/{case_id}/activities",
        headers=analyst,
        json={"type": "escalation", "detail": "Needs escalation"},
    )
    assert denied_escalation.status_code == 403

    allowed_escalation = client.post(
        f"/api/cases/{case_id}/activities",
        headers=senior,
        json={"type": "escalation", "detail": "Escalated to incident response"},
    )
    assert allowed_escalation.status_code == 200

    denied_feedback = client.post(
        f"/api/cases/{case_id}/activities",
        headers=analyst,
        json={"type": "detection-feedback", "detail": "Add rule coverage"},
    )
    assert denied_feedback.status_code == 403

    allowed_feedback = client.post(
        f"/api/cases/{case_id}/activities",
        headers=senior,
        json={"type": "detection-feedback", "detail": "Add rule regression coverage"},
    )
    assert allowed_feedback.status_code == 200

    timeline = client.get(
        f"/api/cases/{case_id}/timeline",
        headers=viewer,
    )
    assert timeline.status_code == 200
    types = {item["type"] for item in timeline.json()["timeline"]}
    assert "escalation" in types
    assert "detection-feedback" in types


def test_invalid_case_activity_is_rejected(tmp_path):
    db = tmp_path / "soc.db"
    case_id = "TL-BAD-ACTIVITY"
    upsert_case(db, new_case(case_id), source="manual")

    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        case_id=case_id,
        command_db=db,
        rules_dir=ROOT / "detections",
    )
    client = TestClient(app)

    response = client.post(
        f"/api/cases/{case_id}/activities",
        json={"type": "auto-close", "detail": "Must not be permitted"},
    )
    assert response.status_code == 400
    assert "Unsupported case activity" in response.json()["detail"]
