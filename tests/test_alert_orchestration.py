from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

from socmind.command_center import case_detail
from socmind.io import load_jsonl
from socmind.orchestration import orchestrate_alert_sqlite
from socmind.production_ops import AlertRecord


ROOT = Path(__file__).resolve().parents[1]


def test_sqlite_alert_orchestration_creates_correlates_escalates_and_deduplicates(tmp_path):
    db = tmp_path / "soc.db"
    evidence_dir = tmp_path / "evidence"
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    base = events[0]

    first = AlertRecord(
        alert_id="ALERT-001",
        source="wazuh",
        timestamp=base.timestamp,
        title="Repeated authentication failures",
        severity=8,
        host=base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="AUTH-FAIL",
    )
    first_result = orchestrate_alert_sqlite(
        db,
        first,
        events,
        evidence_dir=evidence_dir,
    )
    assert first_result.created is True
    assert first_result.duplicate is False
    assert first_result.priority == "P2"
    assert first_result.evidence_count > 0

    second = AlertRecord(
        alert_id="ALERT-002",
        source="wazuh",
        timestamp=base.timestamp + timedelta(minutes=2),
        title="Authentication followed by suspicious activity",
        severity=13,
        host=base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="AUTH-FOLLOWUP",
    )
    second_result = orchestrate_alert_sqlite(
        db,
        second,
        events,
        evidence_dir=evidence_dir,
    )
    assert second_result.created is False
    assert second_result.duplicate is False
    assert second_result.case_id == first_result.case_id
    assert second_result.correlation_score >= 55
    assert second_result.correlation_reasons

    detail = case_detail(db, first_result.case_id)
    assert detail["case"]["priority"] == "P1"
    assert len(detail["alerts"]) == 2
    assert detail["alerts"][1]["alert_id"] == "ALERT-002"
    assert detail["alerts"][1]["correlation_score"] >= 55
    assert detail["alerts"][1]["correlation_reasons"]

    duplicate = orchestrate_alert_sqlite(
        db,
        second,
        events,
        evidence_dir=evidence_dir,
    )
    assert duplicate.duplicate is True
    assert duplicate.case_id == first_result.case_id

    after = case_detail(db, first_result.case_id)
    assert len(after["alerts"]) == 2


def test_weak_similarity_does_not_merge_unrelated_alerts(tmp_path):
    db = tmp_path / "soc.db"
    evidence_dir = tmp_path / "evidence"
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    base = events[0]

    first = AlertRecord(
        "A-1",
        "wazuh",
        base.timestamp,
        "First alert",
        8,
        base.host,
        rule_id="RULE-1",
    )
    second = AlertRecord(
        "A-2",
        "wazuh",
        base.timestamp + timedelta(minutes=2),
        "Second alert",
        8,
        base.host,
        rule_id="RULE-2",
    )
    a = orchestrate_alert_sqlite(db, first, events, evidence_dir=evidence_dir)
    b = orchestrate_alert_sqlite(db, second, events, evidence_dir=evidence_dir)

    assert a.case_id != b.case_id
    assert b.created is True
    assert b.correlation_score == 0
    assert b.correlation_reasons[0]["key"] == "new-case"


def test_concurrent_correlated_alerts_collapse_into_one_sqlite_case(tmp_path):
    db = tmp_path / "soc.db"
    evidence_dir = tmp_path / "evidence"
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    base = events[0]

    alerts = [
        AlertRecord(
            f"CONCURRENT-{idx}",
            "wazuh",
            base.timestamp + timedelta(seconds=idx),
            f"Concurrent alert {idx}",
            10,
            base.host,
            user=base.user,
            src_ip=base.src_ip,
            rule_id=f"RULE-{idx}",
        )
        for idx in (1, 2)
    ]

    def run(alert):
        return orchestrate_alert_sqlite(
            db,
            alert,
            events,
            evidence_dir=evidence_dir,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, alerts))

    assert len({item.case_id for item in results}) == 1
    assert sum(1 for item in results if item.created) == 1
    detail = case_detail(db, results[0].case_id)
    assert len(detail["alerts"]) == 2
