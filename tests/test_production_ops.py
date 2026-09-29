from datetime import timedelta
from pathlib import Path

from socmind.io import load_jsonl
from socmind.production_ops import (
    AlertRecord,
    alert_from_event,
    alert_priority,
    alert_from_event,
    collect_evidence_window,
    correlate_alerts,
)


ROOT = Path(__file__).resolve().parents[1]


def test_alert_priority_mapping():
    assert alert_priority(13) == "P1"
    assert alert_priority(8) == "P2"
    assert alert_priority(3) == "P3"


def test_alert_correlation_is_explainable():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    first = AlertRecord(
        "A-1", "wazuh", events[0].timestamp, "Auth failures", 12,
        events[0].host, user=events[0].user, src_ip=events[0].src_ip,
        rule_id="1001",
    )
    second = AlertRecord(
        "A-2", "wazuh", events[0].timestamp + timedelta(minutes=3),
        "Follow-up auth", 10, events[0].host,
        user=events[0].user, src_ip=events[0].src_ip, rule_id="1002",
    )
    result = correlate_alerts(first, second)
    assert result.related
    assert result.score >= 55
    keys = {item.key for item in result.reasons}
    assert "same-host" in keys
    assert "same-user" in keys


def test_correlation_respects_time_window():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    a = AlertRecord("A", "wazuh", events[0].timestamp, "one", 12, events[0].host)
    b = AlertRecord(
        "B", "wazuh", events[0].timestamp + timedelta(hours=2),
        "two", 12, events[0].host,
    )
    result = correlate_alerts(a, b, window_minutes=15)
    assert not result.related
    assert result.score == 0


def test_evidence_collection_uses_host_user_and_ip_context():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    alert = AlertRecord(
        "A-1",
        "wazuh",
        events[4].timestamp,
        "Suspicious activity",
        12,
        events[4].host,
        user=events[4].user,
        src_ip=events[4].src_ip,
    )
    window = collect_evidence_window(
        alert,
        events,
        before_minutes=30,
        after_minutes=30,
    )
    assert window.events
    assert all(window.start <= event.timestamp.isoformat() <= window.end for event in window.events)


def test_wazuh_event_can_be_promoted_to_alert():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    event = events[0]
    event.source = "wazuh"
    event.data = {
        "wazuh_rule_id": "5710",
        "wazuh_rule_level": 10,
        "wazuh_rule_description": "Authentication failure",
        "raw": {"id": "wazuh-alert-1", "rule": {"groups": ["authentication_failed"]}},
    }
    alert = alert_from_event(event)
    assert alert.alert_id == "wazuh-alert-1"
    assert alert.rule_id == "5710"
    assert alert.severity == 10


def test_elastic_security_alert_schema_is_promoted_correctly():
    from socmind.adapters.elastic import parse_elastic_ndjson

    events = parse_elastic_ndjson(
        ROOT / "tests/fixtures/elastic-security-alerts.ndjson"
    )
    alert = alert_from_event(events[0])
    assert alert.alert_id == "elastic-sec-001"
    assert alert.rule_id == "elastic-rule-ps-001"
    assert alert.title == "Suspicious PowerShell"
    assert alert.severity == 10
    assert alert_priority(alert.severity) == "P2"
    assert alert.technique == "T1059.001"

    critical = alert_from_event(events[1])
    assert critical.severity == 13
    assert alert_priority(critical.severity) == "P1"


def test_wazuh_mitre_metadata_is_promoted():
    from socmind.adapters.wazuh import wazuh_alert_to_event

    event = wazuh_alert_to_event({
        "id": "wazuh-001",
        "timestamp": "2026-09-28T10:00:00Z",
        "agent": {"name": "WS-01"},
        "rule": {
            "id": "60122",
            "level": 12,
            "description": "Credential attack",
            "mitre": {"id": ["T1110"]},
        },
        "data": {"srcip": "198.51.100.22", "dstuser": "analyst"},
    })
    alert = alert_from_event(event)
    assert alert.alert_id == "wazuh-001"
    assert alert.technique == "T1110"
    assert alert.severity == 12
