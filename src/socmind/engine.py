from __future__ import annotations

import base64
import re
from collections import defaultdict
from datetime import timedelta

from .models import Event, Finding

ENCODED_PS = re.compile(r"(?:-|/)e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})", re.I)


def _decode_ps(command: str | None) -> str | None:
    if not command:
        return None
    match = ENCODED_PS.search(command)
    if not match:
        return None
    raw = match.group(1)
    for encoding in ("utf-16le", "utf-8"):
        try:
            return base64.b64decode(raw).decode(encoding, errors="strict")
        except Exception:
            pass
    return None


def analyze(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    by_host: dict[str, list[Event]] = defaultdict(list)
    for event in sorted(events, key=lambda item: item.timestamp):
        by_host[event.host].append(event)

    for host, host_events in by_host.items():
        failures = [event for event in host_events if event.event_id == "4625"]
        successes = [event for event in host_events if event.event_id == "4624"]
        for success in successes:
            related = [
                failure
                for failure in failures
                if failure.user == success.user
                and failure.src_ip == success.src_ip
                and timedelta(0)
                <= success.timestamp - failure.timestamp
                <= timedelta(minutes=10)
            ]
            if len(related) >= 5:
                findings.append(
                    Finding(
                        title="Repeated failed logons followed by successful authentication",
                        severity="high",
                        score=min(95, 55 + len(related)),
                        rationale=[
                            f"{len(related)} failed logons preceded a successful logon within 10 minutes",
                            f"Target user: {success.user or 'unknown'}",
                            f"Source IP: {success.src_ip or 'unknown'}",
                        ],
                        techniques=["T1110 Brute Force", "T1078 Valid Accounts"],
                        evidence=[*related, success],
                    )
                )

        ssh_failures = [event for event in host_events if event.event_id == "ssh_auth_failed"]
        ssh_successes = [event for event in host_events if event.event_id == "ssh_auth_success"]
        for success in ssh_successes:
            related = [
                failure
                for failure in ssh_failures
                if failure.user == success.user
                and failure.src_ip == success.src_ip
                and timedelta(0)
                <= success.timestamp - failure.timestamp
                <= timedelta(minutes=10)
            ]
            if len(related) >= 5:
                findings.append(
                    Finding(
                        title="Repeated SSH failures followed by successful authentication",
                        severity="high",
                        score=min(95, 58 + len(related)),
                        rationale=[
                            f"{len(related)} SSH failures preceded a successful login within 10 minutes",
                            f"Target user: {success.user or 'unknown'}",
                            f"Source IP: {success.src_ip or 'unknown'}",
                        ],
                        techniques=[
                            "T1110 Brute Force",
                            "T1078 Valid Accounts",
                            "T1021.004 SSH",
                        ],
                        evidence=[*related, success],
                    )
                )

        powershell = [
            event
            for event in host_events
            if (event.process or "").lower().endswith("powershell.exe")
            and (
                event.event_id == "1"
                or bool(event.command_line)
            )
        ]
        for ps_event in powershell:
            reasons: list[str] = []
            score = 35
            decoded = _decode_ps(ps_event.command_line)
            command = (ps_event.command_line or "").lower()

            if decoded:
                reasons.append("PowerShell command contains decodable encoded content")
                score += 25
            if "-w hidden" in command or "-windowstyle hidden" in command:
                reasons.append("PowerShell window configured as hidden")
                score += 15
            if "-nop" in command or "-noprofile" in command:
                reasons.append("PowerShell profile loading disabled")
                score += 10

            follow_on = [
                event
                for event in host_events
                if event.dst_ip
                and timedelta(0)
                <= event.timestamp - ps_event.timestamp
                <= timedelta(minutes=2)
            ]
            if follow_on:
                reasons.append(
                    f"{len(follow_on)} outbound connection event(s) followed PowerShell execution"
                )
                score += 15

            if reasons:
                findings.append(
                    Finding(
                        title="Suspicious PowerShell execution",
                        severity="high" if score >= 70 else "medium",
                        score=min(score, 100),
                        rationale=reasons
                        + ([f"Decoded content: {decoded[:160]}"] if decoded else []),
                        techniques=["T1059.001 PowerShell"],
                        evidence=[ps_event, *follow_on],
                    )
                )

        persistence = [
            event for event in host_events if event.event_id in {"4698", "7045"}
        ]
        for event in persistence:
            findings.append(
                Finding(
                    title="Persistence-related Windows system change",
                    severity="medium",
                    score=60,
                    rationale=[f"Observed Windows event {event.event_id} on {host}"],
                    techniques=[
                        "T1053.005 Scheduled Task/Job"
                        if event.event_id == "4698"
                        else "T1543.003 Windows Service"
                    ],
                    evidence=[event],
                )
            )

        for event in host_events:
            if event.event_id == "sudo_command":
                command = event.command_line or str(event.data.get("command", ""))
                suspicious_tokens = (
                    "/etc/shadow",
                    "useradd",
                    "usermod",
                    "chmod 4777",
                    "chown root",
                    "systemctl enable",
                )
                matched = [
                    token for token in suspicious_tokens if token in command.lower()
                ]
                if matched:
                    findings.append(
                        Finding(
                            title="Suspicious privileged Linux command",
                            severity="medium",
                            score=65,
                            rationale=[
                                f"Privileged command executed by {event.user or 'unknown'}",
                                f"Matched high-interest token(s): {', '.join(matched)}",
                            ],
                            techniques=["T1548.003 Sudo and Sudo Caching"],
                            evidence=[event],
                        )
                    )
            elif event.event_id in {"systemd_service_created", "cron_job_created"}:
                technique = (
                    "T1543.002 Systemd Service"
                    if event.event_id == "systemd_service_created"
                    else "T1053.003 Cron"
                )
                findings.append(
                    Finding(
                        title="Persistence-related Linux system change",
                        severity="medium",
                        score=62,
                        rationale=[
                            f"Observed {event.event_id.replace('_', ' ')} on {host}"
                        ],
                        techniques=[technique],
                        evidence=[event],
                    )
                )

    return sorted(findings, key=lambda finding: finding.score, reverse=True)
