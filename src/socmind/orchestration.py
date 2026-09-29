from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .case_workflow import new_case
from .command_center import connect, upsert_case
from .enterprise_command_center import _connect, upsert_case_pg
from .models import Event
from .postgres_store import initialize_postgres
from .production_ops import (
    AlertRecord,
    CorrelationResult,
    alert_fingerprint,
    alert_priority,
    case_id_for_alert,
    collect_evidence_window,
    correlate_alerts,
)


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    case_id: str
    created: bool
    duplicate: bool
    priority: str
    correlation_score: int
    correlation_reasons: list[dict]
    evidence_count: int
    evidence_path: str


def _event_key(event: Event) -> tuple:
    return (
        event.timestamp.isoformat(),
        event.source,
        event.event_id,
        event.host,
        event.user,
        event.process,
        event.parent_process,
        event.src_ip,
        event.dst_ip,
        event.command_line,
    )


def _event_payload(event: Event) -> dict:
    return {
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_id": event.event_id,
        "host": event.host,
        "user": event.user,
        "process": event.process,
        "parent_process": event.parent_process,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "command_line": event.command_line,
        "data": event.data,
    }


def _load_existing_evidence(path: Path) -> list[Event]:
    if not path.is_file():
        return []
    from .io import load_jsonl

    return load_jsonl(path)


def _merge_evidence(path: Path, events: list[Event]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = _load_existing_evidence(path)
    merged: dict[tuple, Event] = {
        _event_key(event): event for event in existing
    }
    for event in events:
        merged[_event_key(event)] = event

    ordered = sorted(merged.values(), key=lambda item: item.timestamp)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as fh:
        for event in ordered:
            fh.write(json.dumps(_event_payload(event), ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    temp.replace(path)
    return len(ordered)


def _priority_rank(value: str) -> int:
    return {"P1": 1, "P2": 2, "P3": 3}.get(value, 3)


def _stronger_priority(left: str, right: str) -> str:
    return left if _priority_rank(left) <= _priority_rank(right) else right


def _row_to_alert(row) -> AlertRecord:
    ts = row["timestamp"]
    if isinstance(ts, str):
        timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    else:
        timestamp = ts
    return AlertRecord(
        alert_id=row["alert_id"],
        source=row["source"],
        timestamp=timestamp,
        title=row["title"],
        severity=int(row["severity"]),
        host=row["host"],
        user=row.get("user") if hasattr(row, "get") else row["user"],
        process=row.get("process") if hasattr(row, "get") else row["process"],
        src_ip=row.get("src_ip") if hasattr(row, "get") else row["src_ip"],
        dst_ip=row.get("dst_ip") if hasattr(row, "get") else row["dst_ip"],
        technique=row.get("technique") if hasattr(row, "get") else row["technique"],
        rule_id=row.get("rule_id") if hasattr(row, "get") else row["rule_id"],
        raw_reference=row.get("raw_reference") if hasattr(row, "get") else row["raw_reference"],
    )


def _best_match(alert: AlertRecord, candidates: list[tuple[str, AlertRecord]]) -> tuple[str | None, CorrelationResult]:
    best_case: str | None = None
    best = CorrelationResult(False, 0, [])
    for case_id, existing in candidates:
        result = correlate_alerts(alert, existing)
        if result.score > best.score:
            best_case = case_id
            best = result
    if not best.related:
        return None, best
    return best_case, best


def _sqlite_duplicate(db_path: str | Path, alert_id: str) -> str | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT case_id FROM case_alerts WHERE alert_id=? LIMIT 1",
            (alert_id,),
        ).fetchone()
        return row["case_id"] if row else None


def _sqlite_candidates(db_path: str | Path) -> list[tuple[str, AlertRecord]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT ca.case_id, a.*
            FROM case_alerts ca
            JOIN alerts a ON a.alert_id=ca.alert_id
            JOIN cases c ON c.case_id=ca.case_id
            WHERE c.state NOT IN ('resolved','false-positive')
            ORDER BY a.timestamp DESC
            LIMIT 500
            """
        ).fetchall()
        return [(row["case_id"], _row_to_alert(row)) for row in rows]


def _sqlite_store_alert(
    db_path: str | Path,
    alert: AlertRecord,
    *,
    case_id: str,
    result: CorrelationResult,
    priority: str,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    reasons = [asdict(item) for item in result.reasons]
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT OR IGNORE INTO alerts(
              alert_id,source,timestamp,title,severity,priority,host,user,process,
              src_ip,dst_ip,technique,rule_id,fingerprint,raw_reference,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                alert.alert_id,
                alert.source,
                alert.timestamp.isoformat(),
                alert.title,
                alert.severity,
                priority,
                alert.host,
                alert.user,
                alert.process,
                alert.src_ip,
                alert.dst_ip,
                alert.technique,
                alert.rule_id,
                alert_fingerprint(alert),
                alert.raw_reference,
                now,
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO case_alerts(
              case_id,alert_id,correlation_score,correlation_reasons,linked_at
            ) VALUES(?,?,?,?,?)
            """,
            (case_id, alert.alert_id, result.score, json.dumps(reasons), now),
        )
        row = conn.execute(
            "SELECT priority FROM cases WHERE case_id=?",
            (case_id,),
        ).fetchone()
        if row:
            upgraded = _stronger_priority(row["priority"], priority)
            conn.execute(
                "UPDATE cases SET priority=?,updated_at=? WHERE case_id=?",
                (upgraded, now, case_id),
            )
        conn.execute(
            """
            INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
            VALUES(?,?,?,?,?)
            """,
            (
                case_id,
                "socmind-orchestrator",
                "alert-linked",
                json.dumps(
                    {
                        "alert_id": alert.alert_id,
                        "source": alert.source,
                        "score": result.score,
                        "reasons": reasons,
                    },
                    ensure_ascii=False,
                )[:5000],
                now,
            ),
        )
        conn.commit()


def orchestrate_alert_sqlite(
    db_path: str | Path,
    alert: AlertRecord,
    events: list[Event],
    *,
    evidence_dir: str | Path,
) -> OrchestrationResult:
    duplicate_case = _sqlite_duplicate(db_path, alert.alert_id)
    priority = alert_priority(alert.severity)
    if duplicate_case:
        path = Path(evidence_dir) / f"{duplicate_case}.jsonl"
        count = len(_load_existing_evidence(path))
        return OrchestrationResult(
            duplicate_case,
            False,
            True,
            priority,
            100,
            [{"key": "duplicate-alert-id", "weight": 100, "detail": alert.alert_id}],
            count,
            str(path.resolve()),
        )

    case_id, correlation = _best_match(alert, _sqlite_candidates(db_path))
    created = case_id is None
    if created:
        case_id = case_id_for_alert(alert)

    evidence_path = Path(evidence_dir) / f"{case_id}.jsonl"
    window = collect_evidence_window(alert, events)
    evidence_count = _merge_evidence(evidence_path, window.events)

    if created:
        upsert_case(
            db_path,
            new_case(case_id, priority=priority),
            source=alert.source,
            title=alert.title,
            evidence_path=evidence_path,
        )
    else:
        with connect(db_path) as conn:
            conn.execute(
                "UPDATE cases SET evidence_path=? WHERE case_id=?",
                (str(evidence_path.resolve()), case_id),
            )
            conn.commit()

    _sqlite_store_alert(
        db_path,
        alert,
        case_id=case_id,
        result=correlation,
        priority=priority,
    )
    return OrchestrationResult(
        case_id,
        created,
        False,
        priority,
        correlation.score,
        [asdict(item) for item in correlation.reasons],
        evidence_count,
        str(evidence_path.resolve()),
    )


def _pg_duplicate(dsn: str, alert_id: str) -> str | None:
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT case_id FROM case_alerts WHERE alert_id=%s LIMIT 1",
                (alert_id,),
            )
            row = cur.fetchone()
            return row["case_id"] if row else None


def _pg_candidates(dsn: str) -> list[tuple[str, AlertRecord]]:
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ca.case_id, a.*
                FROM case_alerts ca
                JOIN alerts a ON a.alert_id=ca.alert_id
                JOIN cases c ON c.case_id=ca.case_id
                WHERE c.state NOT IN ('resolved','false-positive')
                ORDER BY a.timestamp DESC
                LIMIT 500
                """
            )
            rows = cur.fetchall()
    return [(row["case_id"], _row_to_alert(row)) for row in rows]


def _pg_store_alert(
    dsn: str,
    alert: AlertRecord,
    *,
    case_id: str,
    result: CorrelationResult,
    priority: str,
) -> None:
    now = datetime.now(timezone.utc)
    reasons = [asdict(item) for item in result.reasons]
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts(
                  alert_id,source,timestamp,title,severity,priority,host,"user",process,
                  src_ip,dst_ip,technique,rule_id,fingerprint,raw_reference,created_at
                ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(alert_id) DO NOTHING
                """,
                (
                    alert.alert_id,
                    alert.source,
                    alert.timestamp,
                    alert.title,
                    alert.severity,
                    priority,
                    alert.host,
                    alert.user,
                    alert.process,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.technique,
                    alert.rule_id,
                    alert_fingerprint(alert),
                    alert.raw_reference,
                    now,
                ),
            )
            cur.execute(
                """
                INSERT INTO case_alerts(
                  case_id,alert_id,correlation_score,correlation_reasons,linked_at
                ) VALUES(%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT(case_id,alert_id) DO NOTHING
                """,
                (case_id, alert.alert_id, result.score, json.dumps(reasons), now),
            )
            cur.execute(
                "SELECT priority FROM cases WHERE case_id=%s FOR UPDATE",
                (case_id,),
            )
            row = cur.fetchone()
            if row:
                upgraded = _stronger_priority(row["priority"], priority)
                cur.execute(
                    "UPDATE cases SET priority=%s,updated_at=%s WHERE case_id=%s",
                    (upgraded, now, case_id),
                )
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (
                    case_id,
                    "socmind-orchestrator",
                    "alert-linked",
                    json.dumps(
                        {
                            "alert_id": alert.alert_id,
                            "source": alert.source,
                            "score": result.score,
                            "reasons": reasons,
                        },
                        ensure_ascii=False,
                    )[:5000],
                    now,
                ),
            )
        conn.commit()


def orchestrate_alert_postgres(
    dsn: str,
    alert: AlertRecord,
    events: list[Event],
    *,
    evidence_dir: str | Path,
) -> OrchestrationResult:
    initialize_postgres(dsn)
    duplicate_case = _pg_duplicate(dsn, alert.alert_id)
    priority = alert_priority(alert.severity)
    if duplicate_case:
        path = Path(evidence_dir) / f"{duplicate_case}.jsonl"
        count = len(_load_existing_evidence(path))
        return OrchestrationResult(
            duplicate_case,
            False,
            True,
            priority,
            100,
            [{"key": "duplicate-alert-id", "weight": 100, "detail": alert.alert_id}],
            count,
            str(path.resolve()),
        )

    case_id, correlation = _best_match(alert, _pg_candidates(dsn))
    created = case_id is None
    if created:
        case_id = case_id_for_alert(alert)

    evidence_path = Path(evidence_dir) / f"{case_id}.jsonl"
    window = collect_evidence_window(alert, events)
    evidence_count = _merge_evidence(evidence_path, window.events)

    if created:
        upsert_case_pg(
            dsn,
            new_case(case_id, priority=priority),
            source=alert.source,
            title=alert.title,
            evidence_path=str(evidence_path.resolve()),
        )
    else:
        with _connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE cases SET evidence_path=%s WHERE case_id=%s",
                    (str(evidence_path.resolve()), case_id),
                )
            conn.commit()

    _pg_store_alert(
        dsn,
        alert,
        case_id=case_id,
        result=correlation,
        priority=priority,
    )
    return OrchestrationResult(
        case_id,
        created,
        False,
        priority,
        correlation.score,
        [asdict(item) for item in correlation.reasons],
        evidence_count,
        str(evidence_path.resolve()),
    )
