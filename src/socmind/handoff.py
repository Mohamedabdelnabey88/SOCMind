from __future__ import annotations

from .models import Event, Finding
from .triage import triage


def render_shift_handoff(events: list[Event], findings: list[Finding], *, case_id: str) -> str:
    highest = max((f.score for f in findings), default=0)
    priorities = [triage(f).priority for f in findings]
    top_priority = "P1" if "P1" in priorities else "P2" if "P2" in priorities else "P3"

    lines = [
        f"# SOC Shift Handoff — {case_id}",
        "",
        f"- Current priority: {top_priority}",
        f"- Events reviewed: {len(events)}",
        f"- Findings: {len(findings)}",
        f"- Highest score: {highest}",
        "",
        "## What happened",
    ]
    lines += [f"- {finding.title}" for finding in findings[:5]] or ["- No notable findings"]
    lines += ["", "## Next analyst actions"]
    actions = []
    for finding in findings[:3]:
        actions.extend(triage(finding).next_steps[:2])
    lines += [f"- {action}" for action in dict.fromkeys(actions)] or ["- Continue monitoring and document material changes."]
    lines += ["", "## Handoff quality check", "- Evidence source identified", "- Current owner/state documented", "- Outstanding validation gaps preserved"]
    return "\n".join(lines)
