from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(slots=True)
class TriageDecision:
    priority: str
    disposition: str
    escalation: str
    next_steps: list[str]


def triage(finding: Finding) -> TriageDecision:
    title = finding.title.lower()
    steps: list[str] = []

    if "authentication" in title or "ssh" in title or "logon" in title:
        steps = [
            "Validate source IP ownership, ASN, geolocation, and reputation.",
            "Review successful sessions after the failed-authentication burst.",
            "Check MFA outcome and identity-provider sign-in context if available.",
            "Hunt for lateral movement or privilege changes from the affected account.",
        ]
    elif "powershell" in title:
        steps = [
            "Inspect parent and child process ancestry.",
            "Review PowerShell Script Block and Module logs when available.",
            "Extract domains, IPs, URLs, and file hashes from adjacent telemetry.",
            "Check persistence and outbound connections on the same host.",
        ]
    elif "persistence" in title or "service" in title or "cron" in title:
        steps = [
            "Validate whether the change is approved administrative activity.",
            "Inspect creator process, user, file path, arguments, and timestamps.",
            "Search for the same persistence artifact across peer hosts.",
            "Review network and authentication activity immediately before creation.",
        ]
    elif "privileged linux" in title:
        steps = [
            "Confirm whether the sudo command matches an approved change.",
            "Review the invoking user's SSH/session origin.",
            "Inspect account, group, file-permission, and service changes.",
            "Escalate if the privilege change is unexplained or followed by persistence.",
        ]
    else:
        steps = [
            "Validate alert context against surrounding telemetry.",
            "Identify affected user, host, process, and network indicators.",
            "Compare the behavior with known-good administrative activity.",
        ]

    if finding.score >= 80:
        return TriageDecision("P1", "suspicious", "Immediate Tier 2 escalation", steps)
    if finding.score >= 60:
        return TriageDecision("P2", "needs-review", "Tier 1 validate; escalate if unexplained", steps)
    return TriageDecision("P3", "needs-context", "Tier 1 review", steps)
