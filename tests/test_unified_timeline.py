from datetime import datetime, timedelta, timezone

from socmind.unified_timeline import build_unified_case_timeline


def _ts(minutes: int) -> str:
    base = datetime(2026, 9, 29, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(minutes=minutes)).isoformat()


def test_unified_timeline_normalizes_required_fields_and_order():
    detail = {
        "case": {
            "case_id": "TL-001",
            "opened_at": _ts(2),
            "priority": "P2",
            "source": "elastic",
        },
        "alerts": [{
            "alert_id": "A-1",
            "source": "elastic",
            "timestamp": _ts(1),
            "title": "Suspicious authentication",
            "severity": 8,
            "priority": "P2",
            "correlation_score": 0,
        }],
        "audit": [{
            "actor": "socmind-orchestrator",
            "action": "alert-linked",
            "detail": '{"alert_id":"A-1","source":"elastic","created_case":true,"correlation_score":0,"correlation_reasons":[]}',
            "timestamp": _ts(2),
        }, {
            "actor": "tier1",
            "action": "acknowledged",
            "detail": "Case acknowledged",
            "timestamp": _ts(3),
        }, {
            "actor": "lead",
            "action": "assigned",
            "detail": "Assigned to tier2",
            "timestamp": _ts(4),
        }, {
            "actor": "tier2",
            "action": "state-transition",
            "detail": "investigating -> contained | reason: Isolated endpoint",
            "timestamp": _ts(7),
        }, {
            "actor": "tier2",
            "action": "state-transition",
            "detail": "contained -> resolved | reason: Scope validated",
            "timestamp": _ts(9),
        }, {
            "actor": "lead",
            "action": "escalated",
            "detail": "Escalated to IR due to privileged account impact",
            "timestamp": _ts(6),
        }, {
            "actor": "lead",
            "action": "detection-feedback-recorded",
            "detail": "Add regression for observed authentication chain",
            "timestamp": _ts(10),
        }],
        "notes": [{
            "author": "tier2",
            "text": "Validated identity context",
            "created_at": _ts(5),
        }],
        "evidence_collections": [{
            "provider": "elastic",
            "source_ref": "logs-*",
            "status": "completed",
            "event_count": 12,
            "started_at": _ts(4),
            "completed_at": _ts(5),
        }],
        "evidence_requirements": [],
    }
    investigation = {
        "findings": [{
            "title": "Password spray followed by success",
            "severity": "high",
            "score": 80,
            "techniques": ["T1110 Brute Force"],
            "detected_at": _ts(3),
            "source": "elastic",
        }],
        "timeline": [{
            "timestamp": _ts(0),
            "source": "elastic",
            "event_id": "4625",
            "host": "host-1",
            "user": "alice",
            "process": None,
            "src_ip": "192.0.2.10",
            "dst_ip": None,
            "command_line": None,
        }],
    }

    timeline = build_unified_case_timeline(detail, investigation)
    timestamps = [
        datetime.fromisoformat(item["timestamp"])
        for item in timeline
        if item["timestamp"]
    ]
    assert timestamps == sorted(timestamps)

    required = {"timestamp", "type", "source", "actor", "detail"}
    assert all(required <= set(item) for item in timeline)

    types = {item["type"] for item in timeline}
    assert {
        "evidence-event",
        "alert-received",
        "case-created",
        "detection-event",
        "analyst-acknowledged",
        "assignment",
        "note",
        "evidence-collected",
        "escalation",
        "containment",
        "resolution",
        "detection-feedback",
    } <= types


def test_orchestrator_audit_distinguishes_created_vs_correlated_alert():
    detail = {
        "case": {
            "case_id": "TL-002",
            "opened_at": _ts(0),
            "priority": "P2",
            "source": "wazuh",
        },
        "alerts": [
            {
                "alert_id": "A-1",
                "source": "wazuh",
                "timestamp": _ts(0),
                "title": "Root",
                "severity": 8,
                "priority": "P2",
            },
            {
                "alert_id": "A-2",
                "source": "wazuh",
                "timestamp": _ts(2),
                "title": "Follow-up",
                "severity": 13,
                "priority": "P1",
            },
        ],
        "audit": [
            {
                "actor": "socmind-orchestrator",
                "action": "alert-linked",
                "detail": '{"alert_id":"A-1","source":"wazuh","created_case":true,"correlation_score":0,"correlation_reasons":[]}',
                "timestamp": _ts(0),
            },
            {
                "actor": "socmind-orchestrator",
                "action": "alert-linked",
                "detail": '{"alert_id":"A-2","source":"wazuh","created_case":false,"correlation_score":65,"correlation_reasons":[{"detail":"same host","weight":30},{"detail":"same user","weight":20}]}',
                "timestamp": _ts(2),
            },
        ],
        "notes": [],
        "evidence_collections": [],
        "evidence_requirements": [],
    }

    timeline = build_unified_case_timeline(detail)
    created = [item for item in timeline if item["type"] == "case-created"]
    correlated = [item for item in timeline if item["type"] == "alert-correlated"]

    assert len(created) == 1
    assert len(correlated) == 1
    assert "A-2" in correlated[0]["detail"]
    assert "65" in correlated[0]["detail"]
    assert "same host" in correlated[0]["detail"]


def test_note_audit_is_not_double_counted():
    detail = {
        "case": {"opened_at": _ts(0), "priority": "P3", "source": "manual"},
        "alerts": [],
        "evidence_collections": [],
        "evidence_requirements": [],
        "notes": [{
            "author": "analyst",
            "text": "One note",
            "created_at": _ts(1),
        }],
        "audit": [{
            "actor": "analyst",
            "action": "note-added",
            "detail": "One note",
            "timestamp": _ts(1),
        }],
    }
    timeline = build_unified_case_timeline(detail)
    notes = [item for item in timeline if item["type"] == "note"]
    generic_note_audits = [
        item for item in timeline
        if item["type"] == "case-action" and item["title"] == "note-added"
    ]
    assert len(notes) == 1
    assert not generic_note_audits


def test_malformed_timestamp_is_safe_and_sorted_first():
    detail = {
        "case": {"opened_at": "not-a-time", "priority": "P3", "source": "manual"},
        "alerts": [],
        "audit": [{
            "actor": "analyst",
            "action": "acknowledged",
            "detail": "Case acknowledged",
            "timestamp": _ts(1),
        }],
        "notes": [],
        "evidence_collections": [],
        "evidence_requirements": [],
    }
    timeline = build_unified_case_timeline(detail)
    assert timeline[0]["timestamp"] == "not-a-time"
    assert timeline[1]["type"] == "analyst-acknowledged"
