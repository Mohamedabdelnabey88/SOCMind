from pathlib import Path
import json

from socmind.workspace import build_workspace


ROOT = Path(__file__).resolve().parents[1]


def test_build_workspace_creates_complete_case_package(tmp_path):
    target = build_workspace(
        ROOT / "examples/attack_chain.jsonl",
        tmp_path / "workspace",
        case_id="INC-TEST-001",
        priority="P1",
        owner="tier2",
    )

    expected = {
        "case-state.json",
        "case.json",
        "escalation.md",
        "shift-handoff.md",
        "evidence-provenance.json",
        "workspace-summary.json",
    }
    assert expected.issubset({p.name for p in target.iterdir()})

    summary = json.loads((target / "workspace-summary.json").read_text(encoding="utf-8"))
    assert summary["case_id"] == "INC-TEST-001"
    assert summary["priority"] == "P1"
    assert summary["owner"] == "tier2"
    assert summary["findings"] > 0
