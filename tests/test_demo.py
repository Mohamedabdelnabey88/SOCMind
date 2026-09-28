from pathlib import Path

from socmind.command_center import command_center_snapshot, case_detail
from socmind.demo import create_demo


ROOT = Path(__file__).resolve().parents[1]


def test_demo_builds_multi_case_operational_environment(tmp_path):
    result = create_demo(
        tmp_path / "demo",
        windows_events=ROOT / "examples/attack_chain.jsonl",
        linux_events=ROOT / "examples/linux_attack_chain.jsonl",
    )

    db = Path(result["database"])
    assert db.exists()

    snap = command_center_snapshot(db)
    assert snap["summary"]["total"] == 3
    assert snap["summary"]["p1_active"] == 1
    assert snap["summary"]["unassigned"] == 1

    detail = case_detail(db, "DEMO-P1-001")
    assert detail["notes"]
    assert detail["audit"]
    assert detail["case"]["evidence_path"]
