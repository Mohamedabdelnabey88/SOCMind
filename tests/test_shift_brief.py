from pathlib import Path

from socmind.case_workflow import new_case
from socmind.command_center import command_center_snapshot, upsert_case
from socmind.lead_metrics import lead_snapshot
from socmind.shift_brief import render_shift_brief


ROOT = Path(__file__).resolve().parents[1]


def test_shift_brief_contains_operations_detection_and_priority_queue(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(
        db,
        new_case("INC-001", priority="P1", owner="tier2"),
        source="wazuh",
        title="Authentication anomaly",
    )

    command = command_center_snapshot(db)
    lead = lead_snapshot(
        ROOT / "examples/attack_chain.jsonl",
        rules_dir=ROOT / "detections",
        dispositions_path=ROOT / "examples/dispositions.jsonl",
    )
    text = render_shift_brief(command, lead)

    assert "SOCMind Shift Brief" in text
    assert "Detection Health" in text
    assert "Priority Queue" in text
    assert "INC-001" in text
