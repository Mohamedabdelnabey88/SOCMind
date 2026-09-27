from __future__ import annotations

from .models import Event


def render_timeline(events: list[Event]) -> str:
    ordered = sorted(events, key=lambda e: e.timestamp)
    lines = ["SOCMind Evidence Timeline", "=" * 25]
    for event in ordered:
        actor = event.user or "-"
        detail = event.command_line or event.process or event.dst_ip or event.src_ip or ""
        lines.append(
            f"{event.timestamp.isoformat()} | {event.host} | {event.source} | "
            f"{event.event_id} | user={actor} | {detail}"
        )
    return "\n".join(lines)
