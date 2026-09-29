from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event


def _dig(raw: dict, *parts):
    value = raw
    for part in parts:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_elastic_hit(raw: dict) -> Event:
    """Normalize one Elasticsearch/OpenSearch ECS hit into a SOCMind Event."""
    source = raw.get("_source") if isinstance(raw.get("_source"), dict) else raw
    return Event(
        timestamp=_ts(source.get("@timestamp")),
        source="elastic-ecs",
        event_id=str(
            _dig(source, "event", "code")
            or _dig(source, "rule", "id")
            or "elastic_event"
        ),
        host=str(
            _dig(source, "host", "name")
            or _dig(source, "agent", "name")
            or "elastic-host"
        ),
        user=_dig(source, "user", "name"),
        process=_dig(source, "process", "executable")
        or _dig(source, "process", "name"),
        parent_process=_dig(source, "process", "parent", "executable")
        or _dig(source, "process", "parent", "name"),
        src_ip=_dig(source, "source", "ip"),
        dst_ip=_dig(source, "destination", "ip"),
        command_line=_dig(source, "process", "command_line"),
        data={
            "ecs": source,
            "elastic_id": raw.get("_id"),
            "elastic_index": raw.get("_index"),
        },
    )


def parse_elastic_hits(hits: list[dict]) -> list[Event]:
    return [parse_elastic_hit(hit) for hit in hits if isinstance(hit, dict)]


def parse_elastic_ndjson(path: str | Path) -> list[Event]:
    """Parse ECS-shaped Elastic NDJSON documents."""
    events: list[Event] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        events.append(parse_elastic_hit(json.loads(line)))
    return events
