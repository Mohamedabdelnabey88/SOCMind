from pathlib import Path

from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def build_client(tmp_path, *, token=None):
    db = tmp_path / "soc.db"
    upsert_case(
        db,
        new_case("INC-001", priority="P1"),
        source="wazuh",
        title="Authentication investigation",
        evidence_path=ROOT / "examples/attack_chain.jsonl",
    )
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        case_id="INC-001",
        command_db=db,
        rules_dir=ROOT / "detections",
        dispositions_path=ROOT / "examples/dispositions.jsonl",
        api_token=token,
    )
    return TestClient(app), db


def test_case_search_detail_and_actions(tmp_path):
    client, _ = build_client(tmp_path)

    queue = client.get("/api/command-center?q=Authentication")
    assert queue.status_code == 200
    assert len(queue.json()["queue"]) == 1

    detail = client.get("/api/cases/INC-001")
    assert detail.status_code == 200
    assert detail.json()["investigation"]["findings"]

    assert client.post("/api/cases/INC-001/acknowledge").status_code == 200
    assert client.post(
        "/api/cases/INC-001/assign",
        json={"owner": "tier2", "actor": "lead"},
    ).status_code == 200
    assert client.post(
        "/api/cases/INC-001/transition",
        json={"state": "triage", "actor": "tier2"},
    ).status_code == 200
    assert client.post(
        "/api/cases/INC-001/notes",
        json={"author": "tier2", "text": "Validated source and identity context."},
    ).status_code == 200

    updated = client.get("/api/cases/INC-001").json()
    assert updated["case"]["owner"] == "tier2"
    assert updated["case"]["state"] == "triage"
    assert updated["notes"]
    assert len(updated["audit"]) >= 4


def test_api_token_protects_workspace_endpoints(tmp_path):
    client, _ = build_client(tmp_path, token="secret-token")
    assert client.get("/health").status_code == 200
    assert client.get("/api/case").status_code == 401
    assert client.get(
        "/api/case",
        headers={"X-SOCMind-Token": "secret-token"},
    ).status_code == 200
