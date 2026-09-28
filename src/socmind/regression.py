from __future__ import annotations

import json
import re
from pathlib import Path

from .detection_replay import replay_detection
from .detections import DetectionRule
from .engine import analyze
from .models import Event


def _event_dict(event: Event) -> dict:
    return {
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_id": event.event_id,
        "host": event.host,
        "user": event.user,
        "process": event.process,
        "parent_process": event.parent_process,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "command_line": event.command_line,
        "data": event.data,
    }


def _slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower())
    return value.strip("-") or "candidate"


def _candidate_event(events: list[Event], gap_technique: str | None) -> Event:
    if gap_technique == "T1110":
        return next(
            (item for item in events if item.event_id in {"4625", "ssh_auth_failed"}),
            events[0],
        )
    if gap_technique == "T1078":
        return next(
            (item for item in events if item.event_id in {"4624", "ssh_auth_success"}),
            events[0],
        )
    if gap_technique == "T1021.004":
        return next(
            (item for item in events if item.event_id == "ssh_auth_success"),
            events[0],
        )
    return next(
        (item for item in events if item.command_line or item.process or item.event_id),
        events[0],
    )


def _candidate_rule(events: list[Event], gap_technique: str | None) -> str:
    event = _candidate_event(events, gap_technique)
    rule_id = f"socmind-candidate-{_slug(gap_technique or event.event_id)}"
    lines = [
        f"title: Candidate Detection for {gap_technique or event.event_id}",
        f"id: {rule_id}",
        "status: experimental",
        "logsource:",
        "  product: generic",
        "detection:",
        "  selection:",
    ]
    if event.command_line:
        needle = event.command_line.split()[0].replace("'", "''")
        lines += ["    CommandLine|contains:", f"      - '{needle}'"]
    elif event.process:
        image = event.process.replace("'", "''")
        lines += ["    Image|endswith:", f"      - '{image}'"]
    else:
        lines += [f"    EventID: '{event.event_id}'"]
    lines += ["  condition: selection"]
    if gap_technique:
        lines += ["tags:", f"  - attack.{gap_technique.lower()}"]
    lines += [
        "falsepositives:",
        "  - Requires analyst validation and environment-specific tuning",
        "level: medium",
    ]
    return "\n".join(lines) + "\n"


def generate_regression_package(
    events: list[Event],
    rules: list[DetectionRule],
    output_dir: str | Path,
    *,
    case_id: str,
) -> Path:
    if not events:
        raise ValueError("Cannot generate regression package without events")

    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    ordered = sorted(events, key=lambda item: item.timestamp)
    findings = analyze(ordered)
    replay = replay_detection(ordered, rules)
    first_gap = replay.gap_techniques[0] if replay.gap_techniques else None

    events_path = root / "regression-events.jsonl"
    with events_path.open("w", encoding="utf-8") as fh:
        for event in ordered:
            fh.write(json.dumps(_event_dict(event), ensure_ascii=False) + "\n")

    (root / "attack-chain.json").write_text(
        json.dumps(
            {
                "case_id": case_id,
                "events": [_event_dict(event) for event in ordered],
                "findings": [
                    {
                        "title": finding.title,
                        "score": finding.score,
                        "techniques": finding.techniques,
                    }
                    for finding in findings
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / "coverage-before.json").write_text(
        json.dumps(
            {
                "observed_techniques": replay.observed_techniques,
                "covered_techniques": replay.covered_techniques,
                "gap_techniques": replay.gap_techniques,
                "visibility_percent": replay.visibility_percent,
                "first_detection_step": replay.first_detection_step,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / "regression-fixture.json").write_text(
        json.dumps(
            {
                "name": f"{case_id} confirmed incident regression",
                "events": "regression-events.jsonl",
                "expected_min_findings": max(1, len(findings)),
                "expected_techniques": replay.observed_techniques,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / "candidate-detection.yml").write_text(
        _candidate_rule(ordered, first_gap),
        encoding="utf-8",
    )
    (root / "validation-checklist.md").write_text(
        "\n".join(
            [
                f"# Detection Validation Checklist — {case_id}",
                "",
                "- [ ] Confirm the candidate rule is scoped to the intended telemetry source.",
                "- [ ] Run against the generated regression-events.jsonl.",
                "- [ ] Test representative benign/admin activity.",
                "- [ ] Confirm ATT&CK mapping is justified by evidence.",
                "- [ ] Record expected false positives.",
                "- [ ] Compare current vs proposed pack with socmind what-if.",
                "- [ ] Promote only after analyst review.",
            ]
        ),
        encoding="utf-8",
    )
    (root / "tuning-notes.md").write_text(
        "\n".join(
            [
                f"# Tuning Notes — {case_id}",
                "",
                f"Observed techniques: {', '.join(replay.observed_techniques) or '-'}",
                f"Current gaps: {', '.join(replay.gap_techniques) or '-'}",
                f"Current visibility: {replay.visibility_percent}%",
                "",
                "The candidate rule is intentionally experimental and must be validated before production use.",
            ]
        ),
        encoding="utf-8",
    )
    return root
