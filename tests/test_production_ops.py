from datetime import datetime, timedelta, timezone
from pathlib import Path

from socmind.models import Event

from socmind.io import load_jsonl
from socmind.production_ops import (
    AlertRecord,
    alert_from_event,
    alert_priority,
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


def test_default_correlation_requires_more_than_host_and_user():
    ts = datetime(2026, 9, 28, 10, 0, tzinfo=timezone.utc)
    left = AlertRecord(
        "A-1", "elastic", ts, "one", 10, "WS-01",
        user="analyst", rule_id="R-1",
    )
    right = AlertRecord(
        "A-2", "elastic", ts + timedelta(minutes=2), "two", 10, "WS-01",
        user="analyst", rule_id="R-2",
    )
    result = correlate_alerts(left, right)
    assert result.score == 50
    assert result.related is False

    stronger = AlertRecord(
        "A-3", "elastic", ts + timedelta(minutes=3), "three", 10, "WS-01",
        user="analyst", process="powershell.exe", rule_id="R-3",
    )
    left_with_process = AlertRecord(
        "A-4", "elastic", ts, "four", 10, "WS-01",
        user="analyst", process="powershell.exe", rule_id="R-4",
    )
    strong_result = correlate_alerts(left_with_process, stronger)
    assert strong_result.score >= 65
    assert strong_result.related is True


def test_evidence_collector_excludes_unrelated_context():
    ts = datetime(2026, 9, 28, 10, 0, tzinfo=timezone.utc)
    alert = AlertRecord(
        "E-1", "wazuh", ts, "Credential alert", 12, "WS-01",
        user="analyst", src_ip="198.51.100.22",
    )
    related = Event(
        timestamp=ts + timedelta(minutes=1),
        source="windows", event_id="4624", host="WS-01", user="analyst",
    )
    unrelated = Event(
        timestamp=ts + timedelta(minutes=1),
        source="windows", event_id="4624", host="WS-99",
        user="other-user", src_ip="203.0.113.200",
    )
    outside = Event(
        timestamp=ts + timedelta(hours=1),
        source="windows", event_id="1", host="WS-01", user="analyst",
    )
    window = collect_evidence_window(alert, [related, unrelated, outside])
    assert window.events == [related]


def test_same_host_rule_and_technique_do_not_auto_merge_without_context_anchor():
    ts = datetime(2026, 9, 28, 10, 0, tzinfo=timezone.utc)
    first = AlertRecord("NOISY-1","elastic",ts,"Shared server detection",10,"SHARED-SERVER",technique="T1059.001",rule_id="POWERSHELL-RULE")
    second = AlertRecord("NOISY-2","elastic",ts + timedelta(minutes=2),"Shared server detection",10,"SHARED-SERVER",technique="T1059.001",rule_id="POWERSHELL-RULE")
    result = correlate_alerts(first, second)
    assert result.score == 55
    assert result.related is False


def test_unknown_context_does_not_justify_correlation():
    from datetime import datetime, timezone
    now=datetime.now(timezone.utc)
    a=AlertRecord('a','wazuh',now,'Unknown',8,'unknown',user='unknown',process='unknown',rule_id='same')
    b=AlertRecord('b','wazuh',now,'Unknown',8,'unknown',user='unknown',process='unknown',rule_id='same')
    assert not correlate_alerts(a,b).related


def test_missing_source_ids_use_full_context_not_just_second_and_rule():
    from socmind.adapters.wazuh import wazuh_alert_to_event
    raw={'timestamp':'2026-09-29T10:00:00Z','rule':{'id':'one','level':8},'agent':{'name':'host-a'}}
    first=alert_from_event(wazuh_alert_to_event(raw))
    other=alert_from_event(wazuh_alert_to_event({**raw,'agent':{'name':'host-b'}}))
    assert first.alert_id != other.alert_id
    assert first.alert_id == alert_from_event(wazuh_alert_to_event(raw)).alert_id


def test_best_match_prefers_eligible_candidate_and_stable_tie_break():
    from datetime import datetime, timezone
    from socmind.orchestration import _best_match
    now=datetime.now(timezone.utc)
    incoming=AlertRecord('new','wazuh',now,'New',8,'host',user='alice',process='cmd',rule_id='rule',technique='T1000')
    weak=AlertRecord('weak','wazuh',now,'Weak',8,'host',rule_id='rule',technique='T1000')
    eligible=AlertRecord('good','wazuh',now,'Good',8,'other',user='alice',process='cmd',rule_id='rule')
    case_id,result=_best_match(incoming,[('weak',weak),('z',eligible),('a',eligible)],window_minutes=15,threshold=40)
    assert result.related and case_id=='a'
