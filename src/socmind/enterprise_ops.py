from __future__ import annotations

import json
import sqlite3
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
    if source.resolve() == target.resolve():
        raise ValueError("Backup destination must be different from the source database")
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(source)) as source_conn:
        with sqlite3.connect(str(target)) as target_conn:
            source_conn.backup(target_conn)
    return target


def retention_scan(
    directory: str | Path,
    *,
    days: int,
    apply: bool = False,
    suffixes: tuple[str, ...] = (".jsonl", ".json", ".md"),
) -> RetentionResult:
    root = Path(directory)
    if not root.is_dir():
        raise NotADirectoryError(root)
    root_resolved = root.resolve()
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))
    scanned = eligible = deleted = 0

    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root_resolved)
        except (FileNotFoundError, ValueError):
            continue
        scanned += 1
        modified = datetime.fromtimestamp(resolved.stat().st_mtime, timezone.utc)
        if modified < cutoff:
            eligible += 1
            if apply:
                resolved.unlink()
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

CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  title TEXT NOT NULL,
  severity INTEGER NOT NULL,
  priority TEXT NOT NULL,
  host TEXT NOT NULL,
  "user" TEXT,
  process TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  technique TEXT,
  rule_id TEXT,
  fingerprint TEXT NOT NULL,
  raw_reference TEXT,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS case_alerts (
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  correlation_score INTEGER NOT NULL,
  correlation_reasons JSONB NOT NULL,
  linked_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS evidence_requests (
  request_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  description TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  owner TEXT,
  priority TEXT NOT NULL,
  status TEXT NOT NULL,
  due_at TIMESTAMPTZ,
  resolution_note TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS evidence_collections (
  id BIGSERIAL PRIMARY KEY,
  collection_id TEXT NOT NULL UNIQUE,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  window_end TIMESTAMPTZ NOT NULL,
  query_json JSONB NOT NULL,
  status TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 0,
  total_hits INTEGER,
  truncated BOOLEAN NOT NULL DEFAULT FALSE,
  error TEXT,
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cases_priority_state ON cases(priority, state);
CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner);
CREATE INDEX IF NOT EXISTS idx_notes_case ON case_notes(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_case ON case_audit(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_host_time ON alerts(LOWER(host), timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_user_time ON alerts(LOWER("user"), timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_process_time ON alerts(LOWER(process), timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_time ON alerts(src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_time ON alerts(dst_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_time ON alerts(LOWER(rule_id), timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_technique_time ON alerts(LOWER(technique), timestamp);
CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON case_alerts(alert_id);
CREATE INDEX IF NOT EXISTS idx_evidence_collections_case ON evidence_collections(case_id, started_at);
CREATE INDEX IF NOT EXISTS idx_evidence_requests_case ON evidence_requests(case_id, status, due_at);
CREATE INDEX IF NOT EXISTS idx_evidence_requests_owner ON evidence_requests(owner, status);
"""
