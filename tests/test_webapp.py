from pathlib import Path

from fastapi.testclient import TestClient

from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_web_dashboard_health_and_case_api():
    app = create_app(ROOT / "examples/attack_chain.jsonl", case_id="WEB-TEST")
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["case_id"] == "WEB-TEST"

    case = client.get("/api/case")
    assert case.status_code == 200
    payload = case.json()
    assert payload["case_id"] == "WEB-TEST"
    assert payload["findings"]
    assert payload["graph"]["nodes"]


def test_web_dashboard_serves_index():
    app = create_app(ROOT / "examples/attack_chain.jsonl")
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "SOCMind" in response.text
    assert "Evidence Graph" in response.text
