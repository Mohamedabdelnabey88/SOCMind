from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event

FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")


def _journal_timestamp(raw: dict) -> datetime:
    micros = raw.get("__REALTIME_TIMESTAMP")
    if micros is not None:
        return datetime.fromtimestamp(int(micros) / 1_000_000, tz=timezone.utc)
    value = raw.get("_SOURCE_REALTIME_TIMESTAMP")
    if value is not None:
        return datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc)
    return datetime.now(timezone.utc)


def parse_journald_json(path: str | Path) -> list[Event]:
    events: list[Event] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        msg = str(raw.get("MESSAGE", ""))
        host = str(raw.get("_HOSTNAME", raw.get("HOSTNAME", "linux-host")))
        unit = str(raw.get("_SYSTEMD_UNIT", ""))
        process = str(raw.get("_COMM", "")) or None
        user = None
        src_ip = None
        event_id = "journal_event"

        failed = FAILED.search(msg)
        accepted = ACCEPTED.search(msg)
        if failed:
            event_id = "ssh_auth_failed"
            user = failed.group("user")
            src_ip = failed.group("ip")
        elif accepted:
            event_id = "ssh_auth_success"
            user = accepted.group("user")
            src_ip = accepted.group("ip")
        elif unit.endswith(".service") and ("Created symlink" in msg or "Started" in msg):
            event_id = "systemd_service_activity"

        events.append(Event(
            timestamp=_journal_timestamp(raw),
            source="journald",
            event_id=event_id,
            host=host,
            user=user,
            src_ip=src_ip,
            process=process,
            data={"message": msg, "unit": unit},
        ))
    return events
