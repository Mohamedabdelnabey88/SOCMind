from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .detections import DetectionRule, evaluate_rule
from .io import load_jsonl


@dataclass(slots=True)
class RuleTestResult:
    name: str
    passed: bool
    expected_matches: int
    actual_matches: int


def run_rule_test(rule: DetectionRule, fixture: str | Path) -> RuleTestResult:
    raw = json.loads(Path(fixture).read_text(encoding="utf-8"))
    events_path = Path(fixture).parent / raw["events"]
    events = load_jsonl(events_path)
    actual = len(evaluate_rule(rule, events))
    expected = int(raw["expected_matches"])
    return RuleTestResult(
        name=str(raw.get("name", Path(fixture).stem)),
        passed=actual == expected,
        expected_matches=expected,
        actual_matches=actual,
    )
