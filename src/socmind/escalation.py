from __future__ import annotations

from pathlib import Path

from .hypothesis import generate_hypotheses
from .ioc import extract_iocs
from .models import Event, Finding
from .triage import triage


def render_escalation_package(
    events: list[Event],
    findings: list[Finding],
    *,
    case_id: str,
) -> str:
    lines = [
        f"# SOCMind Escalation Package — {case_id}",
        "",
        "## Executive Summary",
        f"- Events reviewed: {len(events)}",
        f"- Findings: {len(findings)}",
        f"- Highest risk score: {max((f.score for f in findings), default=0)}",
        "",
        "## Findings",
    ]

    for finding in findings:
        decision = triage(finding)
        lines += [
            f"### {finding.title}",
            f"- Severity: {finding.severity}",
            f"- Score: {finding.score}",
            f"- Priority: {decision.priority}",
            f"- Escalation: {decision.escalation}",
            f"- MITRE ATT&CK: {', '.join(finding.techniques) or '-'}",
            "- Evidence:",
        ]
        lines += [f"  - {reason}" for reason in finding.rationale]
        lines.append("")

    lines += ["## IOCs"]
    iocs = extract_iocs(events)
    if iocs:
        lines += [f"- {ioc.type.upper()}: {ioc.value} ({ioc.scope})" for ioc in iocs]
    else:
        lines.append("- None extracted")

    lines += ["", "## Investigation Hypotheses"]
    hypotheses = generate_hypotheses(findings)
    if not hypotheses:
        lines.append("- None generated")
    for item in hypotheses:
        lines.append(f"### {item.name} — {item.confidence}% confidence")
        lines.append("- Supporting:")
        lines += [f"  - {value}" for value in item.supporting]
        lines.append("- Validation gaps:")
        lines += [f"  - {value}" for value in item.contradicting]

    lines += [
        "",
        "## Recommended Handoff",
        "- Validate identity-provider/MFA context where relevant.",
        "- Preserve endpoint and authentication evidence before containment changes.",
        "- Scope related users, hosts, processes and network indicators.",
        "- Document containment decisions and evidence in the case record.",
    ]
    return "\n".join(lines)


def export_escalation_package(
    events: list[Event],
    findings: list[Finding],
    output: str | Path,
    *,
    case_id: str,
) -> None:
    Path(output).write_text(
        render_escalation_package(events, findings, case_id=case_id),
        encoding="utf-8",
    )
