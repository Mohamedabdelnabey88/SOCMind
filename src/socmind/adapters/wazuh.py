from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event


def _ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def wazuh_alert_to_event(raw: dict) -> Event:
    data = raw.get("data") or {}
    win = data.get("win") or {}
    system = win.get("system") or {}
    eventdata = win.get("eventdata") or {}
    agent = raw.get("agent") or {}
    rule = raw.get("rule") or {}

    event_id = (
        system.get("eventID")
        or data.get("event_id")
        or rule.get("id")
        or "wazuh_alert"
    )
    host = (
        agent.get("name")
        or system.get("computer")
        or data.get("hostname")
        or "wazuh-host"
    )

    return Event(
        timestamp=_ts(raw.get("timestamp") or raw.get("@timestamp")),
        source="wazuh",
        event_id=str(event_id),
        host=str(host),
        user=eventdata.get("targetUserName")
        or eventdata.get("subjectUserName")
        or data.get("srcuser")
        or data.get("dstuser"),
        process=eventdata.get("image")
        or eventdata.get("newProcessName")
        or data.get("process"),
        parent_process=eventdata.get("parentImage")
        or eventdata.get("parentProcessName"),
        src_ip=eventdata.get("ipAddress") or data.get("srcip") or raw.get("srcip"),
        dst_ip=eventdata.get("destinationIp") or data.get("dstip") or raw.get("dstip"),
        command_line=eventdata.get("commandLine")
        or data.get("command")
        or data.get("full_log"),
        data={
            "wazuh_rule_id": rule.get("id"),
            "wazuh_rule_level": rule.get("level"),
            "wazuh_rule_description": rule.get("description"),
            "raw": raw,
        },
    )


def wazuh_search_hits_to_events(hits: list[dict]) -> list[Event]:
    events: list[Event] = []
    for hit in hits:
        source = hit.get("_source") if isinstance(hit.get("_source"), dict) else hit
        raw = dict(source)
        if hit.get("_id") is not None and "id" not in raw:
            raw["id"] = hit.get("_id")
        events.append(wazuh_alert_to_event(raw))
    return events


def parse_wazuh_alerts(path: str | Path) -> list[Event]:
    """Parse Wazuh alert JSONL/NDJSON into SOCMind's normalized event model."""
    events: list[Event] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        events.append(wazuh_alert_to_event(json.loads(line)))
    return events
