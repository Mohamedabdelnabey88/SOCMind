from datetime import datetime, timezone

from socmind.escalation import render_escalation_package
from socmind.models import Event, Finding


def test_escalation_package_contains_handoff_context():
    event = Event(
        datetime(2026, 9, 28, tzinfo=timezone.utc),
        "sysmon",
        "1",
        "WS-01",
        process="powershell.exe",
        dst_ip="203.0.113.77",
    )
    finding = Finding(
        "Suspicious PowerShell execution",
        "high",
        80,
        ["Hidden window"],
        ["T1059.001 PowerShell"],
        [event],
    )
    report = render_escalation_package([event], [finding], case_id="INC-001")
    assert "INC-001" in report
    assert "Recommended Handoff" in report
    assert "T1059.001" in report
