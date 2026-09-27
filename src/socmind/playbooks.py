from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True, slots=True)
class PlaybookStep:
    phase: str
    action: str


def select_playbook(finding: Finding) -> list[PlaybookStep]:
    title = finding.title.lower()

    if "authentication" in title or "ssh" in title or "logon" in title:
        return [
            PlaybookStep("Validate", "Confirm user, source IP, device, MFA and login context."),
            PlaybookStep("Scope", "Search the source IP and account across authentication telemetry."),
            PlaybookStep("Investigate", "Review activity immediately after the successful session."),
            PlaybookStep("Escalate", "Escalate when post-authentication behavior is unexplained."),
        ]

    if "powershell" in title:
        return [
            PlaybookStep("Validate", "Inspect parent process and command-line provenance."),
            PlaybookStep("Decode", "Review encoded or obfuscated content safely."),
            PlaybookStep("Scope", "Hunt child processes, files, DNS and outbound connections."),
            PlaybookStep("Escalate", "Escalate when execution or network behavior lacks business justification."),
        ]

    if "persistence" in title or "service" in title:
        return [
            PlaybookStep("Validate", "Check approved deployment/change-management records."),
            PlaybookStep("Investigate", "Identify creator account/process and artifact path."),
            PlaybookStep("Scope", "Search peer endpoints for the same task/service artifact."),
            PlaybookStep("Escalate", "Escalate unexplained persistence with surrounding evidence."),
        ]

    return [
        PlaybookStep("Validate", "Confirm the event and surrounding context."),
        PlaybookStep("Scope", "Search related users, hosts, processes and indicators."),
        PlaybookStep("Document", "Record evidence supporting closure or escalation."),
    ]
