from .models import Finding
from .triage import triage


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "SOCMind: no notable findings."

    lines = ["SOCMind Investigation Summary", "=" * 29]
    for idx, finding in enumerate(findings, 1):
        decision = triage(finding)
        lines += [
            "",
            f"[{idx}] {finding.severity.upper()} | score={finding.score} | {finding.title}",
            f"Priority: {decision.priority}",
            f"Disposition: {decision.disposition}",
            f"Escalation: {decision.escalation}",
            "MITRE: " + ", ".join(finding.techniques),
            "Why it fired:",
        ]
        lines += [f"  - {reason}" for reason in finding.rationale]
        lines.append("Recommended next steps:")
        lines += [f"  {step_idx}. {step}" for step_idx, step in enumerate(decision.next_steps, 1)]
        lines.append(f"Evidence events: {len(finding.evidence)}")
    return "\n".join(lines)
