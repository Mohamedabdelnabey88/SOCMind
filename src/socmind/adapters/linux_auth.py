from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event

FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")
SUDO = re.compile(r"(?P<user>\S+)\s*:\s*TTY=.*COMMAND=(?P<command>.+)$")


def _timestamp_from_prefix(line: str, year: int) -> datetime:
    # Traditional syslog timestamps do not include a year or timezone.
    stamp = line[:15]
    dt = datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def parse_auth_log(path: str | Path, *, host: str = "linux-host", year: int | None = None) -> list[Event]:
    year = year or datetime.now(timezone.utc).year
    events: list[Event] = []
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if len(raw) < 16:
            continue
        try:
            ts = _timestamp_from_prefix(raw, year)
        except ValueError:
            continue

        failed = FAILED.search(raw)
        if failed:
            events.append(Event(ts, "linux-auth", "ssh_auth_failed", host,
                                user=failed.group("user"), src_ip=failed.group("ip"),
                                data={"raw": raw}))
            continue

        accepted = ACCEPTED.search(raw)
        if accepted:
            events.append(Event(ts, "linux-auth", "ssh_auth_success", host,
                                user=accepted.group("user"), src_ip=accepted.group("ip"),
                                data={"raw": raw}))
            continue

        sudo = SUDO.search(raw)
        if "sudo" in raw and sudo:
            events.append(Event(ts, "linux-auth", "sudo_command", host,
                                user=sudo.group("user"),
                                command_line=sudo.group("command").strip(),
                                data={"raw": raw}))
    return events
