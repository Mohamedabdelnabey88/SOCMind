import json
from datetime import datetime
from pathlib import Path

from .models import Event


def load_jsonl(path: str | Path) -> list[Event]:
    events: list[Event] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            try:
                events.append(Event(
                    timestamp=datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00")),
                    source=raw.get("source", "unknown"),
                    event_id=str(raw.get("event_id", "")),
                    host=raw.get("host", "unknown"),
                    user=raw.get("user"),
                    process=raw.get("process"),
                    parent_process=raw.get("parent_process"),
                    src_ip=raw.get("src_ip"),
                    dst_ip=raw.get("dst_ip"),
                    command_line=raw.get("command_line"),
                    data=raw.get("data", {}),
                ))
            except KeyError as exc:
                raise ValueError(f"Missing required field {exc.args[0]!r} on line {line_no}") from exc
    return events
