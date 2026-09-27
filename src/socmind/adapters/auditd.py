from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event

AUDIT_TIME = re.compile(r"audit\((?P<epoch>\d+)(?:\.\d+)?:")
TYPE = re.compile(r"type=(?P<type>[A-Z_]+)")
FIELD = re.compile(r'(?P<key>[a-zA-Z_]+)=(?:"(?P<quoted>[^"]*)"|(?P<plain>\S+))')


def parse_auditd(path: str | Path, *, host: str = "linux-host") -> list[Event]:
    events: list[Event] = []
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        ts_match = AUDIT_TIME.search(raw)
        if not ts_match:
            continue
        timestamp = datetime.fromtimestamp(int(ts_match.group("epoch")), tz=timezone.utc)
        fields = {}
        for match in FIELD.finditer(raw):
            fields[match.group("key")] = match.group("quoted") if match.group("quoted") is not None else match.group("plain")
        event_type = TYPE.search(raw)
        type_name = event_type.group("type") if event_type else "AUDIT"
        event_id = f"auditd_{type_name.lower()}"
        command = fields.get("proctitle") or fields.get("comm") or fields.get("exe")
        events.append(Event(
            timestamp=timestamp,
            source="auditd",
            event_id=event_id,
            host=fields.get("node", host),
            user=fields.get("acct") or fields.get("uid"),
            process=fields.get("exe") or fields.get("comm"),
            command_line=command,
            data={"audit_type": type_name, **fields, "raw": raw},
        ))
    return events
