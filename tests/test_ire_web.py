from pathlib import Path

from fastapi.testclient import TestClient

from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_ire_web_apis_expose_replay_blind_spots_whatif_and_quality():
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        rules_dir=ROOT / "detections",
        proposed_rules_dir=ROOT / "examples/proposed-rules",
        quality_checklist_path=ROOT / "examples/quality-checklist.json",
    )
    client = TestClient(app)

    replay = client.get("/api/ire/replay")
    assert replay.status_code == 200
    assert replay.json()["summary"]["steps"] > 0

    detection = client.get("/api/ire/detection-replay")
    assert detection.status_code == 200
    assert detection.json()["first_detection_step"] is not None
    assert detection.json()["gap_techniques"]

    what_if = client.get("/api/ire/what-if")
    assert what_if.status_code == 200
    payload = what_if.json()
    assert payload["enabled"] is True
    assert payload["first_detection_step_improvement"] > 0
    assert payload["visibility_delta"] > 0

    quality = client.get("/api/ire/quality")
    assert quality.status_code == 200
    assert quality.json()["completed"] > 0
    assert quality.json()["total"] >= 10


def test_ire_what_if_is_optional():
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        rules_dir=ROOT / "detections",
    )
    client = TestClient(app)
    payload = client.get("/api/ire/what-if").json()
    assert payload["enabled"] is False
