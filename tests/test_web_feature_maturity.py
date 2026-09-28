from pathlib import Path

from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_professional_web_apis_expose_pagination_quality_and_rule_audit(tmp_path):
    db = tmp_path / "soc.db"
    evidence = ROOT / "examples/attack_chain.jsonl"

    for index in range(35):
        upsert_case(
            db,
            new_case(f"CASE-{index:03d}", priority="P2"),
            title=f"Professional case {index:03d}",
            evidence_path=evidence if index == 0 else None,
        )

    app = create_app(
        evidence,
        case_id="CURRENT-001",
        command_db=db,
        rules_dir=ROOT / "detections",
        quality_checklist_path=ROOT / "examples/quality-checklist.json",
    )
    client = TestClient(app)

    queue = client.get("/api/command-center?limit=10&offset=10")
    assert queue.status_code == 200
    payload = queue.json()
    assert payload["pagination"]["matched"] == 35
    assert payload["pagination"]["returned"] == 10
    assert payload["pagination"]["offset"] == 10
    assert payload["pagination"]["has_more"] is True

    audit = client.get("/api/detections/audit")
    assert audit.status_code == 200
    assert audit.json()["production_ready"] is True
    assert audit.json()["errors"] == 0

    quality = client.get("/api/ire/quality")
    assert quality.status_code == 200
    assert quality.json()["readiness"] in {"READY", "NEEDS_REVIEW"}
    assert quality.json()["closure_allowed"] is True

    replay = client.get("/api/ire/detection-replay")
    assert replay.status_code == 200
    replay_payload = replay.json()
    assert replay_payload["technique_visibility"]
    assert "detected_techniques" in replay_payload
    assert "time_to_first_detection_seconds" in replay_payload


def test_similarity_api_supports_minimum_score_threshold(tmp_path):
    db = tmp_path / "soc.db"
    evidence = ROOT / "examples/attack_chain.jsonl"
    upsert_case(
        db,
        new_case("HIST-SAME", priority="P2"),
        title="Same evidence historical case",
        evidence_path=evidence,
    )

    app = create_app(
        evidence,
        case_id="CURRENT-001",
        command_db=db,
        rules_dir=ROOT / "detections",
    )
    client = TestClient(app)

    response = client.get("/api/reasoning/similar?min_score=90&limit=5")
    assert response.status_code == 200
    payload = response.json()
    assert payload["matches"]
    assert payload["matches"][0]["case_id"] == "HIST-SAME"
    assert payload["matches"][0]["score"] == 100.0
    assert payload["matches"][0]["strength"] == "strong"
    assert payload["summary"]["min_score"] == 90.0


def test_per_case_quality_gate_can_block_and_release_case_closure(tmp_path):
    db = tmp_path / "soc.db"
    evidence = ROOT / "examples/attack_chain.jsonl"
    upsert_case(
        db,
        new_case("QUALITY-001", priority="P1"),
        title="Quality enforced case",
        evidence_path=evidence,
    )

    app = create_app(
        evidence,
        case_id="QUALITY-001",
        command_db=db,
        rules_dir=ROOT / "detections",
        enforce_quality_on_close=True,
    )
    client = TestClient(app)

    for state in ("triage", "investigating", "contained"):
        response = client.post(
            "/api/cases/QUALITY-001/transition",
            json={"state": state},
        )
        assert response.status_code == 200

    blocked = client.post(
        "/api/cases/QUALITY-001/transition",
        json={"state": "resolved"},
    )
    assert blocked.status_code == 409
    detail = blocked.json()["detail"]
    assert detail["readiness"] == "BLOCKED"
    assert detail["blockers"]

    complete = {
        "iocs_reviewed": True,
        "process_ancestry_reviewed": True,
        "contradictions_reviewed": True,
        "persistence_validated": True,
        "scope_validated": True,
        "detection_feedback": True,
        "handoff_complete": True,
    }
    saved = client.put(
        "/api/cases/QUALITY-001/quality-checklist",
        json={"checklist": complete},
    )
    assert saved.status_code == 200
    assert saved.json()["review"]["closure_allowed"] is True
    assert saved.json()["review"]["readiness"] == "READY"

    closed = client.post(
        "/api/cases/QUALITY-001/transition",
        json={"state": "resolved"},
    )
    assert closed.status_code == 200
    assert closed.json()["case"]["state"] == "resolved"
