from pathlib import Path

from socmind.case_workflow import new_case
from socmind.command_center import command_center_snapshot, upsert_case
from socmind.detection_replay import replay_detection
from socmind.detections import load_rules
from socmind.io import load_jsonl
from socmind.quality_gate import review_investigation
from socmind.rule_audit import audit_rule_pack
from socmind.similarity import compare_fingerprints, fingerprint_case, find_similar_cases


ROOT = Path(__file__).resolve().parents[1]


def test_detection_replay_distinguishes_tagged_coverage_from_triggering():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    rules = load_rules(ROOT / "detections")
    result = replay_detection(events, rules)

    rows = {item.technique: item for item in result.technique_visibility}
    assert "T1110" in rows
    assert rows["T1110"].state == "gap"
    assert "T1059.001" in rows
    assert rows["T1059.001"].state == "detected"
    assert rows["T1059.001"].first_detected_step is not None
    assert result.time_to_first_detection_seconds is not None
    assert result.first_meaningful_detection_step is not None


def test_quality_gate_blocks_closure_until_required_work_is_complete():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    review = review_investigation(events)
    assert review.readiness == "BLOCKED"
    assert review.closure_allowed is False
    assert review.blockers

    completed = review_investigation(
        events,
        checklist={
            "iocs_reviewed": True,
            "process_ancestry_reviewed": True,
            "contradictions_reviewed": True,
            "persistence_validated": True,
            "scope_validated": True,
            "detection_feedback": True,
            "handoff_complete": True,
        },
    )
    assert completed.closure_allowed is True
    assert completed.readiness in {"READY", "NEEDS_REVIEW"}


def test_similarity_exposes_component_breakdown_and_strength(tmp_path):
    events_path = ROOT / "examples/attack_chain.jsonl"
    events = load_jsonl(events_path)
    score, parts = compare_fingerprints(
        fingerprint_case(events),
        fingerprint_case(events),
    )
    assert score == 100.0
    assert parts == {
        "techniques": 100.0,
        "event_ids": 100.0,
        "processes": 100.0,
        "iocs": 100.0,
    }

    db = tmp_path / "soc.db"
    upsert_case(
        db,
        new_case("HIST-001"),
        title="Identical historical case",
        evidence_path=events_path,
    )
    matches = find_similar_cases(events, db, min_score=50)
    assert matches
    assert matches[0].strength == "strong"
    assert matches[0].shared_dimensions >= 2
    assert matches[0].component_scores["techniques"] == 100.0


def test_case_queue_pagination_preserves_summary_and_filter_count(tmp_path):
    db = tmp_path / "soc.db"
    for index in range(60):
        upsert_case(
            db,
            new_case(f"INC-{index:03d}", priority="P2"),
            title=f"Case {index:03d}",
        )

    first = command_center_snapshot(db, limit=25, offset=0)
    second = command_center_snapshot(db, limit=25, offset=25)
    last = command_center_snapshot(db, limit=25, offset=50)

    assert first["summary"]["total"] == 60
    assert first["pagination"] == {
        "limit": 25,
        "offset": 0,
        "matched": 60,
        "returned": 25,
        "has_more": True,
        "has_previous": False,
    }
    assert second["pagination"]["returned"] == 25
    assert second["pagination"]["has_previous"] is True
    assert last["pagination"]["returned"] == 10
    assert last["pagination"]["has_more"] is False


def test_current_detection_pack_passes_rule_audit():
    result = audit_rule_pack(ROOT / "detections")
    assert result.rules >= 3
    assert result.errors == 0
    assert result.production_ready is True


def test_rule_audit_rejects_duplicate_ids(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    template = """title: {title}
id: duplicated-rule
status: experimental
logsource:
  product: windows
detection:
  selection:
    EventID: "1"
  condition: selection
falsepositives:
  - Administrative activity
tags:
  - attack.t1059
level: medium
"""
    (rules / "one.yml").write_text(
        template.format(title="One"),
        encoding="utf-8",
    )
    (rules / "two.yml").write_text(
        template.format(title="Two"),
        encoding="utf-8",
    )

    result = audit_rule_pack(rules)
    assert result.production_ready is False
    assert result.errors == 2
    assert all(
        issue.code == "duplicate-id"
        for issue in result.issues
        if issue.severity == "error"
    )
