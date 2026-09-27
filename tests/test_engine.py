from datetime import datetime, timezone

from socmind.engine import analyze
from socmind.models import Event


def win_ev(minute: int, event_id: str, **kwargs):
    return Event(
        datetime(2026, 9, 28, 12, minute, tzinfo=timezone.utc),
        "windows",
        event_id,
        "WS-023",
        **kwargs,
    )


def linux_ev(minute: int, event_id: str, **kwargs):
    return Event(
        datetime(2026, 9, 28, 13, minute, tzinfo=timezone.utc),
        "linux",
        event_id,
        "LINUX-01",
        **kwargs,
    )


def test_detects_failed_logons_then_success():
    events = [
        win_ev(i, "4625", user="analyst", src_ip="10.0.0.8")
        for i in range(5)
    ]
    events.append(win_ev(6, "4624", user="analyst", src_ip="10.0.0.8"))
    findings = analyze(events)
    assert any("failed logons" in finding.title for finding in findings)


def test_detects_suspicious_powershell_followed_by_network():
    events = [
        win_ev(
            1,
            "1",
            process="powershell.exe",
            command_line="powershell.exe -nop -w hidden",
        ),
        win_ev(2, "3", process="powershell.exe", dst_ip="203.0.113.50"),
    ]
    findings = analyze(events)
    assert any(
        finding.title == "Suspicious PowerShell execution"
        for finding in findings
    )


def test_detects_ssh_failures_then_success():
    events = [
        linux_ev(
            i,
            "ssh_auth_failed",
            user="ops",
            src_ip="198.51.100.23",
        )
        for i in range(5)
    ]
    events.append(
        linux_ev(
            6,
            "ssh_auth_success",
            user="ops",
            src_ip="198.51.100.23",
        )
    )
    findings = analyze(events)
    assert any("SSH failures" in finding.title for finding in findings)


def test_detects_suspicious_sudo_command():
    findings = analyze(
        [
            linux_ev(
                1,
                "sudo_command",
                user="ops",
                command_line="sudo useradd backup-admin",
            )
        ]
    )
    assert any(
        finding.title == "Suspicious privileged Linux command"
        for finding in findings
    )


def test_detects_linux_persistence():
    findings = analyze(
        [linux_ev(1, "systemd_service_created", user="root")]
    )
    assert any(
        finding.title == "Persistence-related Linux system change"
        for finding in findings
    )
