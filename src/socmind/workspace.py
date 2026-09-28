from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .case import export_case
from .case_workflow import new_case, save_case
from .engine import analyze
from .escalation import export_escalation_package
from .handoff import render_shift_handoff
from .io import load_jsonl
from .provenance import fingerprint


def build_workspace(
    events_path: str | Path,
    output_dir: str | Path,
    *,
    case_id: str,
    priority: str = "P2",
    owner: str | None = None,
) -> Path:
    source = Path(events_path)
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)

    events = load_jsonl(source)
    findings = analyze(events)

    case = new_case(case_id, priority=priority, owner=owner)
    save_case(case, target / "case-state.json")
    export_case(events, findings, target / "case.json", case_id=case_id)
    export_escalation_package(
        events,
        findings,
        target / "escalation.md",
        case_id=case_id,
    )
    (target / "shift-handoff.md").write_text(
        render_shift_handoff(events, findings, case_id=case_id),
        encoding="utf-8",
    )

    evidence = fingerprint(source)
    (target / "evidence-provenance.json").write_text(
        json.dumps(asdict(evidence), indent=2),
        encoding="utf-8",
    )

    summary = {
        "case_id": case_id,
        "priority": priority,
        "owner": owner,
        "events": len(events),
        "findings": len(findings),
        "highest_score": max((f.score for f in findings), default=0),
        "artifacts": [
            "case-state.json",
            "case.json",
            "escalation.md",
            "shift-handoff.md",
            "evidence-provenance.json",
        ],
    }
    (target / "workspace-summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    return target
