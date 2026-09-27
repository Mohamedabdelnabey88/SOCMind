from datetime import datetime, timezone

from socmind.graph import build_graph, render_mermaid
from socmind.models import Event


def event(**kwargs):
    return Event(
        timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
        source="test",
        event_id=kwargs.pop("event_id", "1"),
        host=kwargs.pop("host", "WS-01"),
        **kwargs,
    )


def test_graph_links_user_host_process_and_network():
    events = [
        event(user="analyst", process="powershell.exe", parent_process="winword.exe"),
        event(process="powershell.exe", dst_ip="203.0.113.10"),
    ]
    nodes, edges = build_graph(events)
    labels = {(n.kind, n.label) for n in nodes}
    relations = {e.relation for e in edges}
    assert ("user", "analyst") in labels
    assert ("process", "powershell.exe") in labels
    assert ("ip", "203.0.113.10") in labels
    assert "spawned" in relations
    assert "connected-to" in relations
    assert "flowchart LR" in render_mermaid(events)
