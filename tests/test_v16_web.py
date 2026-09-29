from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from socmind.io import load_jsonl
from socmind.orchestration import orchestrate_alert_sqlite
from socmind.production_ops import AlertRecord
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_orchestrated_case_exposes_alert_chain_and_unified_timeline(tmp_path):
    db = tmp_path / "soc.db"
    evidence_dir = tmp_path / "evidence"
    events_path = ROOT / "examples/attack_chain.jsonl"
    events = load_jsonl(events_path)
    base = events[0]

    first = AlertRecord(
        "WEB-ALERT-001",
        "wazuh",
        base.timestamp,
        "Authentication failures",
        8,
        base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="WEB-AUTH-1",
    )
    first_result = orchestrate_alert_sqlite(
        db,
        first,
        events,
        evidence_dir=evidence_dir,
    )

    second = AlertRecord(
        "WEB-ALERT-002",
        "wazuh",
        base.timestamp + timedelta(minutes=2),
        "Follow-up suspicious authentication",
        13,
        base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="WEB-AUTH-2",
    )
    orchestrate_alert_sqlite(
        db,
        second,
        events,
        evidence_dir=evidence_dir,
    )

    app = create_app(
        events_path,
        case_id=first_result.case_id,
        command_db=db,
        rules_dir=ROOT / "detections",
    )
    client = TestClient(app)

    response = client.get(f"/api/cases/{first_result.case_id}")
    assert response.status_code == 200
    payload = response.json()

    assert len(payload["alerts"]) == 2
    assert payload["investigation"]["summary"]["events"] > 0
    assert payload["evidence_integrity"]["available"] is True
    assert payload["evidence_integrity"]["valid"] is True

    integrity_response = client.get(
        f"/api/cases/{first_result.case_id}/evidence-integrity"
    )
    assert integrity_response.status_code == 200
    assert integrity_response.json()["valid"] is True

    timeline = payload["case_timeline"]
    assert timeline

    kinds = {item["kind"] for item in timeline}
    assert "case" in kinds
    assert "alert" in kinds
    assert "evidence" in kinds
    assert "case-action" in kinds

    alert_entries = [item for item in timeline if item["kind"] == "alert"]
    assert len(alert_entries) == 2
    assert any("correlation" in item["detail"] for item in alert_entries)

    evidence_path = Path(first_result.evidence_path)
    evidence_path.write_text(
        evidence_path.read_text(encoding="utf-8") + '{"tampered":true}\\n',
        encoding="utf-8",
    )
    tampered = client.get(
        f"/api/cases/{first_result.case_id}/evidence-integrity"
    )
    assert tampered.status_code == 200
    tampered_payload = tampered.json()
    assert tampered_payload["available"] is True
    assert tampered_payload["valid"] is False
    assert "sha256 mismatch" in tampered_payload["errors"]


def test_web_reports_v16_api_version():
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        rules_dir=ROOT / "detections",
    )
    assert app.version == "1.6.0"
