from pathlib import Path

from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_reasoning_web_apis_return_contradictions_and_similar_cases(tmp_path):
    db = tmp_path / "soc.db"
    windows = ROOT / "examples/attack_chain.jsonl"
    linux = ROOT / "examples/linux_attack_chain.jsonl"

    upsert_case(
        db,
        new_case("HIST-WIN", priority="P2"),
        source="wazuh",
        title="Historical Windows compromise",
        evidence_path=windows,
    )
    upsert_case(
        db,
        new_case("HIST-LINUX", priority="P2"),
        source="elastic",
        title="Historical Linux SSH case",
        evidence_path=linux,
    )

    app = create_app(
        windows,
        case_id="CURRENT-001",
        command_db=db,
        rules_dir=ROOT / "detections",
    )
    client = TestClient(app)

    contradictions = client.get("/api/reasoning/contradictions")
    assert contradictions.status_code == 200
    contradiction_payload = contradictions.json()
    assert contradiction_payload["summary"]["hypotheses"] > 0
    assert contradiction_payload["summary"]["validation_gaps"] > 0

    similar = client.get("/api/reasoning/similar")
    assert similar.status_code == 200
    payload = similar.json()
    assert payload["enabled"] is True
    assert payload["matches"]
    assert payload["matches"][0]["case_id"] == "HIST-WIN"
    assert "not attribution" in payload["interpretation"]


def test_similarity_web_api_reports_disabled_without_command_db():
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        rules_dir=ROOT / "detections",
    )
    client = TestClient(app)
    payload = client.get("/api/reasoning/similar").json()
    assert payload["enabled"] is False
