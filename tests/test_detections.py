from pathlib import Path

from socmind.detections import evaluate_rule, load_rule
from socmind.io import load_jsonl
from socmind.rule_tests import run_rule_test


ROOT = Path(__file__).resolve().parents[1]


def test_sigma_subset_loads_and_matches():
    rule = load_rule(ROOT / "detections/windows/suspicious-powershell.yml")
    events = load_jsonl(ROOT / "tests/fixtures/rule-events.jsonl")
    matches = evaluate_rule(rule, events)
    assert len(matches) == 1
    assert matches[0].process.lower().endswith("powershell.exe")
    assert "T1059.001" in rule.attack_techniques


def test_rule_fixture_harness():
    rule = load_rule(ROOT / "detections/windows/suspicious-powershell.yml")
    result = run_rule_test(rule, ROOT / "tests/fixtures/powershell-rule-test.json")
    assert result.passed
    assert result.actual_matches == result.expected_matches == 1
