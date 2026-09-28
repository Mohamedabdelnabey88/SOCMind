from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RetentionResult:
    scanned: int
    eligible: int
    deleted: int
    dry_run: bool


def backup_sqlite(database: str | Path, output: str | Path) -> Path:
    source = Path(database)
    if not source.is_file():
        raise FileNotFoundError(source)
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return target


def retention_scan(
    directory: str | Path,
    *,
    days: int,
    apply: bool = False,
    suffixes: tuple[str, ...] = (".jsonl", ".json", ".md"),
) -> RetentionResult:
    root = Path(directory)
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))
    scanned = eligible = deleted = 0

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        scanned += 1
        modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        if modified < cutoff:
            eligible += 1
            if apply:
                path.unlink()
                deleted += 1

    return RetentionResult(scanned, eligible, deleted, not apply)


def render_retention(result: RetentionResult) -> str:
    mode = "DRY-RUN" if result.dry_run else "APPLIED"
    return (
        f"SOCMind Retention | {mode}\n"
        f"scanned={result.scanned}\n"
        f"eligible={result.eligible}\n"
        f"deleted={result.deleted}"
    )


def postgres_schema() -> str:
    return """CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  priority TEXT NOT NULL,
  owner TEXT,
  opened_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  source TEXT,
  title TEXT,
  acknowledged_at TIMESTAMPTZ,
  evidence_path TEXT
);

CREATE TABLE IF NOT EXISTS case_notes (
  id BIGSERIAL PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  author TEXT NOT NULL,
  text TEXT NOT NULL,
  disposition TEXT,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS case_audit (
  id BIGSERIAL PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cases_priority_state ON cases(priority, state);
CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner);
CREATE INDEX IF NOT EXISTS idx_notes_case ON case_notes(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_case ON case_audit(case_id, timestamp);
"""
