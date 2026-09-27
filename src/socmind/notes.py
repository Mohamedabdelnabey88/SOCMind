from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class AnalystNote:
    case_id: str
    author: str
    text: str
    created_at: str
    disposition: str | None = None


def append_note(
    path: str | Path,
    *,
    case_id: str,
    author: str,
    text: str,
    disposition: str | None = None,
) -> AnalystNote:
    note = AnalystNote(
        case_id=case_id,
        author=author,
        text=text,
        created_at=datetime.now(timezone.utc).isoformat(),
        disposition=disposition,
    )
    with Path(path).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(note), ensure_ascii=False) + "\n")
    return note


def load_notes(path: str | Path) -> list[AnalystNote]:
    notes: list[AnalystNote] = []
    source = Path(path)
    if not source.exists():
        return notes
    for line in source.read_text(encoding="utf-8").splitlines():
        if line.strip():
            notes.append(AnalystNote(**json.loads(line)))
    return notes
