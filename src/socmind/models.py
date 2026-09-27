from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Event:
    timestamp: datetime
    source: str
    event_id: str
    host: str
    user: str | None = None
    process: str | None = None
    parent_process: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    command_line: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    score: int
    rationale: list[str]
    techniques: list[str]
    evidence: list[Event]
