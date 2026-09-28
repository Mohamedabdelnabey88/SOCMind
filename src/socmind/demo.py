from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from .case_workflow import CaseState
from .command_center import acknowledge_case, add_case_note, upsert_case


def create_demo(
    output_dir: str | Path,
    *,
    windows_events: str | Path,
    linux_events: str | Path,
) -> dict:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    db = root / "socmind-demo.db"
    now = datetime.now(timezone.utc)

    cases = [
        (
            CaseState(
                "DEMO-P1-001",
                "investigating",
                "mohamed",
                "P1",
                (now - timedelta(minutes=28)).isoformat(),
                now.isoformat(),
            ),
            "wazuh",
            "Failed logons followed by PowerShell and persistence",
            windows_events,
        ),
        (
            CaseState(
                "DEMO-P2-002",
                "triage",
                None,
                "P2",
                (now - timedelta(minutes=12)).isoformat(),
                now.isoformat(),
            ),
            "elastic",
            "Linux SSH authentication anomaly",
            linux_events,
        ),
        (
            CaseState(
                "DEMO-P3-003",
                "resolved",
                "analyst2",
                "P3",
                (now - timedelta(minutes=80)).isoformat(),
                (now - timedelta(minutes=15)).isoformat(),
            ),
            "manual",
            "Resolved administrative activity review",
            windows_events,
        ),
    ]

    for case, source, title, evidence in cases:
        upsert_case(db, case, source=source, title=title, evidence_path=evidence)

    acknowledge_case(db, "DEMO-P1-001", actor="mohamed")
    add_case_note(
        db,
        "DEMO-P1-001",
        author="mohamed",
        text="Correlated authentication failures, PowerShell execution, outbound traffic, and persistence evidence.",
        disposition="needs-review",
    )
    add_case_note(
        db,
        "DEMO-P2-002",
        author="shift-lead",
        text="Validate SSH source and assign an analyst before SLA threshold.",
    )

    return {
        "database": str(db),
        "case_id": "DEMO-P1-001",
        "events": str(Path(windows_events)),
    }
