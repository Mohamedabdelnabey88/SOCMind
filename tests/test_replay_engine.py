from pathlib import Path

from socmind.detection_replay import replay_detection
from socmind.detections import load_rules
from socmind.engine import analyze
from socmind.io import load_jsonl
from socmind.quality_gate import review_investigation
from socmind.regression import generate_regression_package
from socmind.replay import build_investigation_replay
from socmind.whatif import compare_rule_packs


ROOT = Path(__file__).resolve().parents[1]


def test_powershell_network_event_does_not_duplicate_execution_finding():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    findings = analyze(events)
    titles = [finding.title for finding in findings]
    assert titles.count("Suspicious PowerShell execution") == 1


def test_investigation_replay_tracks_findings_and_hypotheses():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    steps = build_investigation_replay(events)
    assert len(steps) == len(events)
    assert any(step.new_findings for step in steps)
    assert any(step.hypotheses for step in steps)


def test_detection_replay_exposes_blind_spots():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    rules = load_rules(ROOT / "detections")
    result = replay_detection(events, rules)
    assert result.meaningful_steps > 0
    assert result.first_detection_step is not None
    assert result.observed_techniques
    assert 0 <= result.visibility_percent <= 100


def test_quality_gate_keeps_analyst_validation_explicit():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    review = review_investigation(events)
    assert review.total >= 10
    assert "Detection feedback completed" in review.outstanding

    completed = review_investigation(
        events,
        checklist={
            "iocs_reviewed": True,
            "persistence_validated": True,
            "scope_validated": True,
            "detection_feedback": True,
            "handoff_complete": True,
        },
    )
    assert completed.completed > review.completed


def test_regression_package_contains_detection_engineering_artifacts(tmp_path):
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    rules = load_rules(ROOT / "detections")
    target = generate_regression_package(
        events,
        rules,
        tmp_path / "regression",
        case_id="INC-001",
    )
    expected = {
        "attack-chain.json",
        "regression-events.jsonl",
        "regression-fixture.json",
        "coverage-before.json",
        "candidate-detection.yml",
        "validation-checklist.md",
        "tuning-notes.md",
    }
    assert expected.issubset({item.name for item in target.iterdir()})


def test_what_if_can_compare_rule_packs():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    rules = load_rules(ROOT / "detections")
    result = compare_rule_packs(events, rules, rules)
    assert result.visibility_delta == 0
    assert result.blind_step_delta == 0
    assert result.newly_covered_techniques == []


def test_proposed_pack_detects_demo_chain_earlier():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    current = load_rules(ROOT / "detections")
    proposed = load_rules(ROOT / "examples/proposed-rules")
    result = compare_rule_packs(events, current, proposed)
    assert result.first_detection_step_improvement is not None
    assert result.first_detection_step_improvement > 0
    assert result.visibility_delta > 0
    assert "T1110" in result.newly_covered_techniques
