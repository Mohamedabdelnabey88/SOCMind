from pathlib import Path

from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_command_center_api_returns_queue_and_metrics(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(
        db,
        new_case("INC-001", priority="P1", owner="tier2"),
        source="wazuh",
        title="Suspicious authentication chain",
    )

    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        case_id="WEB-001",
        command_db=db,
    )
    client = TestClient(app)

    response = client.get("/api/command-center")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["p1_active"] == 1
    assert payload["queue"][0]["case_id"] == "INC-001"
    assert payload["queue"][0]["source"] == "wazuh"


def test_command_center_api_can_be_disabled():
    app = create_app(ROOT / "examples/attack_chain.jsonl")
    client = TestClient(app)
    payload = client.get("/api/command-center").json()
    assert payload["enabled"] is False
