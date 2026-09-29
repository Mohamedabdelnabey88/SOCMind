from pathlib import Path

from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.enterprise_auth import trusted_proxy_headers
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def _headers(secret, subject, role):
    return trusted_proxy_headers(secret, subject, role)


def test_evidence_requirement_web_rbac_and_case_detail(tmp_path):
    db = tmp_path / "soc.db"
    case_id = "WEB-REQ-001"
    upsert_case(
        db,
        new_case(case_id, priority="P2"),
        source="elastic",
        title="Web evidence requirement case",
        evidence_path=ROOT / "examples/attack_chain.jsonl",
    )

    secret = "evidence-rbac-secret"
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        case_id=case_id,
        command_db=db,
        rules_dir=ROOT / "detections",
        auth_mode="trusted-proxy",
        trusted_proxy_secret=secret,
    )
    client = TestClient(app)

    viewer = _headers(secret, "viewer@example.com", "viewer")
    analyst = _headers(secret, "analyst@example.com", "analyst")
    senior = _headers(secret, "senior@example.com", "senior-analyst")
    lead = _headers(secret, "lead@example.com", "lead")

    suggestions = client.get(
        f"/api/cases/{case_id}/evidence-requirements/suggestions",
        headers=viewer,
    )
    assert suggestions.status_code == 200
    assert suggestions.json()["count"] > 0

    denied = client.post(
        f"/api/cases/{case_id}/evidence-requirements/generate",
        headers=viewer,
        json={"due_hours": 4},
    )
    assert denied.status_code == 403

    generated = client.post(
        f"/api/cases/{case_id}/evidence-requirements/generate",
        headers=analyst,
        json={"due_hours": 4},
    )
    assert generated.status_code == 200
    payload = generated.json()
    assert payload["requirement_ids"]
    requirement = payload["evidence_requirements"][0]
    requirement_id = requirement["requirement_id"]
    assert requirement["status"] == "required"

    requested = client.post(
        f"/api/evidence-requirements/{requirement_id}",
        headers=analyst,
        json={"status": "requested", "assigned_to": "identity-team"},
    )
    assert requested.status_code == 200
    row = next(
        item
        for item in requested.json()["evidence_requirements"]
        if item["requirement_id"] == requirement_id
    )
    assert row["status"] == "requested"

    analyst_receive = client.post(
        f"/api/evidence-requirements/{requirement_id}",
        headers=analyst,
        json={
            "status": "received",
            "evidence_reference": "case://WEB-REQ-001/idp/mfa",
        },
    )
    assert analyst_receive.status_code == 403

    senior_receive = client.post(
        f"/api/evidence-requirements/{requirement_id}",
        headers=senior,
        json={
            "status": "received",
            "response_summary": "Identity context received",
            "evidence_reference": "case://WEB-REQ-001/idp/mfa",
        },
    )
    assert senior_receive.status_code == 200

    manual = client.post(
        f"/api/cases/{case_id}/evidence-requirements",
        headers=analyst,
        json={
            "key": "manual-vpn-check",
            "title": "Collect manual VPN check",
            "source": "network",
            "target": "analyst@example.com",
            "rationale": "Validate remote-access path",
            "due_hours": 8,
        },
    )
    assert manual.status_code == 200
    manual_id = manual.json()["requirement_id"]

    senior_waive = client.post(
        f"/api/evidence-requirements/{manual_id}",
        headers=senior,
        json={
            "status": "waived",
            "response_summary": "Attempted waiver",
        },
    )
    assert senior_waive.status_code == 403

    lead_waive = client.post(
        f"/api/evidence-requirements/{manual_id}",
        headers=lead,
        json={
            "status": "waived",
            "response_summary": "Lead accepted documented residual risk",
        },
    )
    assert lead_waive.status_code == 200

    detail = client.get(f"/api/cases/{case_id}", headers=viewer)
    assert detail.status_code == 200
    statuses = {
        item["requirement_id"]: item["status"]
        for item in detail.json()["evidence_requirements"]
    }
    assert statuses[requirement_id] == "received"
    assert statuses[manual_id] == "waived"


def test_received_requirement_requires_evidence_reference(tmp_path):
    db = tmp_path / "soc.db"
    case_id = "WEB-REQ-002"
    upsert_case(
        db,
        new_case(case_id, priority="P3"),
        source="wazuh",
        title="Reference validation",
        evidence_path=ROOT / "examples/attack_chain.jsonl",
    )

    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        case_id=case_id,
        command_db=db,
        rules_dir=ROOT / "detections",
    )
    client = TestClient(app)

    created = client.post(
        f"/api/cases/{case_id}/evidence-requirements",
        json={
            "key": "manual-context",
            "title": "Collect context",
            "source": "identity",
            "rationale": "Missing context",
        },
    )
    assert created.status_code == 200
    requirement_id = created.json()["requirement_id"]

    invalid = client.post(
        f"/api/evidence-requirements/{requirement_id}",
        json={"status": "received"},
    )
    assert invalid.status_code == 400
    assert "evidence_reference is required" in invalid.json()["detail"]
