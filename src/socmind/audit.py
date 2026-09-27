from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


@dataclass(slots=True)
class AuditEntry:
    case_id: str
    actor: str
    action: str
    detail: str
    timestamp: str


def append_audit(path: str | Path, *, case_id: str, actor: str, action: str, detail: str) -> AuditEntry:
    entry = AuditEntry(
        case_id=case_id,
        actor=actor,
        action=action,
        detail=detail,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    with Path(path).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
    return entry


def load_audit(path: str | Path) -> list[AuditEntry]:
    source = Path(path)
    if not source.exists():
        return []
    return [
        AuditEntry(**json.loads(line))
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
