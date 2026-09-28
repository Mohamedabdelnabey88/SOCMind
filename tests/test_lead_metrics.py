from pathlib import Path

from socmind.lead_metrics import detection_health, lead_snapshot
from socmind.tuning import DispositionRecord


ROOT = Path(__file__).resolve().parents[1]


def test_detection_health_flags_noisy_rule():
    records = [
        DispositionRecord("rule-1", "false-positive"),
        DispositionRecord("rule-1", "false-positive"),
        DispositionRecord("rule-1", "false-positive"),
        DispositionRecord("rule-1", "true-positive"),
        DispositionRecord("rule-1", "false-positive"),
    ]
    rows = detection_health(records)
    assert len(rows) == 1
    assert rows[0].noisy is True
    assert rows[0].false_positive_rate == 0.8
    assert rows[0].score < 60


def test_lead_snapshot_contains_coverage_and_top_entities():
    snap = lead_snapshot(
        ROOT / "examples/attack_chain.jsonl",
        rules_dir=ROOT / "detections",
        dispositions_path=ROOT / "examples/dispositions.jsonl",
    )
    assert snap["summary"]["events"] > 0
    assert snap["summary"]["rules"] > 0
    assert snap["summary"]["observed_techniques"] > 0
    assert snap["top_hosts"]
    assert snap["detection_health"]
