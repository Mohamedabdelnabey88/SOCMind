from pathlib import Path

from fastapi.testclient import TestClient

from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_lead_health_api_returns_detection_metrics():
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        rules_dir=ROOT / "detections",
        dispositions_path=ROOT / "examples/dispositions.jsonl",
    )
    client = TestClient(app)

    response = client.get("/api/lead-health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["rules"] > 0
    assert payload["summary"]["observed_techniques"] > 0
    assert payload["detection_health"]
    assert payload["top_hosts"]
