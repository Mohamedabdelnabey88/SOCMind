from pathlib import Path

from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_web_evidence_suggestions_requests_and_rbac(tmp_path):
    db = tmp_path / "soc.db"
    events = ROOT / "examples/attack_chain.jsonl"
    upsert_case(
        db,
        new_case("WEB-EVIDENCE", priority="P1"),
        source="wazuh",
        title="Evidence workflow case",
        evidence_path=events,
    )

    analyst_app = create_app(
        events,
        case_id="WEB-EVIDENCE",
        command_db=db,
        api_token="analyst-secret",
        api_token_role="analyst",
        rules_dir=ROOT / "detections",
    )
    analyst = TestClient(analyst_app)
    headers = {"X-SOCMind-Token": "analyst-secret"}

    suggestions = analyst.get(
        "/api/cases/WEB-EVIDENCE/evidence-suggestions",
        headers=headers,
    )
    assert suggestions.status_code == 200
    assert suggestions.json()["enabled"] is True
    assert suggestions.json()["count"] > 0

    first = analyst.post(
        "/api/cases/WEB-EVIDENCE/evidence-requests/suggest",
        headers=headers,
        json={"due_hours": 4},
    )
    assert first.status_code == 200
    first_ids = first.json()["request_ids"]
    assert first_ids
    assert len(first.json()["evidence_requests"]) == len(set(first_ids))

    second = analyst.post(
        "/api/cases/WEB-EVIDENCE/evidence-requests/suggest",
        headers=headers,
        json={"due_hours": 4},
    )
    assert second.status_code == 200
    assert second.json()["request_ids"] == first_ids
    assert len(second.json()["evidence_requests"]) == len(set(first_ids))

    request_id = first_ids[0]
    started = analyst.post(
        f"/api/evidence-requests/{request_id}",
        headers=headers,
        json={"status": "in-progress", "assigned_to": "identity-team"},
    )
    assert started.status_code == 200

    fulfilled = analyst.post(
        f"/api/evidence-requests/{request_id}",
        headers=headers,
        json={
            "status": "fulfilled",
            "response_summary": "MFA validated from managed device.",
            "evidence_reference": "idp://session/test-1",
        },
    )
    assert fulfilled.status_code == 200
    request = next(
        item
        for item in fulfilled.json()["evidence_requests"]
        if item["request_id"] == request_id
    )
    assert request["status"] == "fulfilled"
    assert request["evidence_reference"] == "idp://session/test-1"

    detail = analyst.get(
        "/api/cases/WEB-EVIDENCE",
        headers=headers,
    ).json()
    kinds = {item["kind"] for item in detail["case_timeline"]}
    assert "evidence-request" in kinds
    assert "evidence-fulfilled" in kinds

    viewer_app = create_app(
        events,
        case_id="WEB-EVIDENCE",
        command_db=db,
        api_token="viewer-secret",
        api_token_role="viewer",
        rules_dir=ROOT / "detections",
    )
    viewer = TestClient(viewer_app)
    viewer_headers = {"X-SOCMind-Token": "viewer-secret"}

    assert viewer.get(
        "/api/cases/WEB-EVIDENCE",
        headers=viewer_headers,
    ).status_code == 200
    denied = viewer.post(
        "/api/cases/WEB-EVIDENCE/evidence-requests/suggest",
        headers=viewer_headers,
        json={},
    )
    assert denied.status_code == 403
