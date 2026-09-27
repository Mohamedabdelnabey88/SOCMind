from datetime import datetime, timezone

from socmind.models import Event
from socmind.process_tree import render_process_tree


def test_process_tree_renders_parent_child_relationship():
    event = Event(
        datetime(2026, 9, 28, tzinfo=timezone.utc),
        "sysmon",
        "1",
        "WS-01",
        process="powershell.exe",
        parent_process="winword.exe",
    )
    output = render_process_tree([event])
    assert "winword.exe" in output
    assert "powershell.exe" in output
