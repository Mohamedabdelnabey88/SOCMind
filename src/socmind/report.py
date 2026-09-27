from .models import Finding


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "SOCMind: no notable findings."
    lines = ["SOCMind Investigation Summary", "=" * 29]
    for idx, finding in enumerate(findings, 1):
        lines += [
            "",
            f"[{idx}] {finding.severity.upper()} | score={finding.score} | {finding.title}",
            "MITRE: " + ", ".join(finding.techniques),
        ]
        lines += [f"- {reason}" for reason in finding.rationale]
        lines.append(f"Evidence events: {len(finding.evidence)}")
    return "\n".join(lines)
