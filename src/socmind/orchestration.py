from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .command_center import connect
from .enterprise_command_center import _connect
from .evidence_integrity import write_evidence_manifest, evidence_manifest_path, verify_evidence_manifest
from .models import Event
from .postgres_store import initialize_postgres
from .production_ops import (
    AlertRecord,
    CorrelationReason,
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


@contextmanager
def _evidence_lock(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as fh:
        if fh.seek(0, os.SEEK_END) == 0:
            fh.write(b"0")
            fh.flush()
        fh.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _load_existing_evidence(path: Path) -> list[Event]:
    if not path.is_file():
        return []
    from .io import load_jsonl

    return load_jsonl(path)


def _merge_evidence(
    path: Path,
    events: list[Event],
    *,
    case_id: str | None = None,
    source: str | None = None,
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    if any(item.is_symlink() for item in [path, *path.parents, path.with_suffix(path.suffix + ".lock")]):
        raise ValueError("Symlink evidence paths are not permitted")
    with _evidence_lock(path):
        if evidence_manifest_path(path).exists():
            if not verify_evidence_manifest(path).valid:
                raise ValueError("Existing evidence failed integrity verification; merge refused")
        existing = _load_existing_evidence(path)
        merged: dict[tuple, Event] = {
            _event_key(event): event for event in existing
        }
        for event in events:
            merged[_event_key(event)] = event

        ordered = sorted(merged.values(), key=lambda item: item.timestamp)
        temp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        with temp.open("w", encoding="utf-8") as fh:
            for event in ordered:
                fh.write(json.dumps(_event_payload(event), ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        temp.replace(path)
        if case_id is not None and source is not None:
            write_evidence_manifest(
                path,
                case_id=case_id,
                source=source,
                event_count=len(ordered),
            )
        return len(ordered)


def _priority_rank(value: str) -> int:
    return {"P1": 1, "P2": 2, "P3": 3}.get(value, 3)


def _stronger_priority(left: str, right: str) -> str:
    return left if _priority_rank(left) <= _priority_rank(right) else right


def _row_to_alert(row) -> AlertRecord:
    ts = row["timestamp"]
    timestamp = (
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if isinstance(ts, str)
        else ts
    )

    def value(key: str):
        return row.get(key) if hasattr(row, "get") else row[key]

    return AlertRecord(
        alert_id=row["alert_id"],
        source=row["source"],
        timestamp=timestamp,
        title=row["title"],
        severity=int(row["severity"]),
        host=row["host"],
        user=value("user"),
        process=value("process"),
        src_ip=value("src_ip"),
        dst_ip=value("dst_ip"),
        technique=value("technique"),
        rule_id=value("rule_id"),
        raw_reference=value("raw_reference"),
    )


def _best_match(
    alert: AlertRecord,
    candidates: list[tuple[str, AlertRecord]],
    *,
    window_minutes: int,
    threshold: int,
) -> tuple[str | None, CorrelationResult]:
    best_case: str | None = None
    best = CorrelationResult(False, 0, [])
    for case_id, existing in candidates:
        result = correlate_alerts(
            alert,
            existing,
            window_minutes=window_minutes,
            threshold=threshold,
        )
        if result.score > best.score:
            best_case = case_id
            best = result
    if not best.related:
        return None, best
    return best_case, best


def _correlation_lock_keys(alert: AlertRecord) -> list[str]:
    keys = {
        f"host:{alert.host.lower()}" if alert.host else "",
        f"user:{alert.user.lower()}" if alert.user else "",
        f"src:{alert.src_ip}" if alert.src_ip else "",
        f"dst:{alert.dst_ip}" if alert.dst_ip else "",
    }
    return sorted(key for key in keys if key)


def _root_result() -> CorrelationResult:
    return CorrelationResult(
        True,
        100,
        [CorrelationReason("root-alert", 100, "Root alert created this case")],
    )


def _new_case_result() -> CorrelationResult:
    return CorrelationResult(
        False,
        0,
        [CorrelationReason(
            "new-case",
            0,
            "No active case met the configured correlation threshold",
        )],
    )



def _sqlite_candidate_rows(
    conn,
    alert: AlertRecord,
    *,
    window_minutes: int,
):
    start = (alert.timestamp - timedelta(minutes=window_minutes)).isoformat()
    end = (alert.timestamp + timedelta(minutes=window_minutes)).isoformat()
    anchors = [("host", alert.host)]
    for column, value in (
        ("user", alert.user),
        ("process", alert.process),
        ("src_ip", alert.src_ip),
        ("dst_ip", alert.dst_ip),
        ("technique", alert.technique),
        ("rule_id", alert.rule_id),
    ):
        if value:
            anchors.append((column, value))
    anchor_sql = " OR ".join(
        f"a.{column} = ? COLLATE NOCASE" for column, _ in anchors
    )
    params = [start, end, *[value for _, value in anchors]]
    return conn.execute(
        f"""
        SELECT ca.case_id, a.*
        FROM case_alerts ca
        JOIN alerts a ON a.alert_id=ca.alert_id
        JOIN cases c ON c.case_id=ca.case_id
        WHERE c.state NOT IN ('resolved','false-positive')
          AND a.timestamp BETWEEN ? AND ?
          AND ({anchor_sql})
        ORDER BY a.timestamp DESC
        LIMIT 2000
        """,
        params,
    ).fetchall()


def _pg_candidate_rows(
    cur,
    alert: AlertRecord,
    *,
    window_minutes: int,
):
    start = alert.timestamp - timedelta(minutes=window_minutes)
    end = alert.timestamp + timedelta(minutes=window_minutes)
    anchors = [("host", alert.host)]
    for column, value in (
        ('"user"', alert.user),
        ("process", alert.process),
        ("src_ip", alert.src_ip),
        ("dst_ip", alert.dst_ip),
        ("technique", alert.technique),
        ("rule_id", alert.rule_id),
    ):
        if value:
            anchors.append((column, value))
    anchor_sql = " OR ".join(
        f"LOWER(a.{column}) = LOWER(%s)" for column, _ in anchors
    )
    params = [start, end, *[value for _, value in anchors]]
    cur.execute(
        f"""
        SELECT ca.case_id, a.*
        FROM case_alerts ca
        JOIN alerts a ON a.alert_id=ca.alert_id
        JOIN cases c ON c.case_id=ca.case_id
        WHERE c.state NOT IN ('resolved','false-positive')
          AND a.timestamp BETWEEN %s AND %s
          AND ({anchor_sql})
        ORDER BY a.timestamp DESC
        LIMIT 2000
        """,
        params,
    )
    return cur.fetchall()


def _sqlite_decide_and_store(
    db_path: str | Path,
    alert: AlertRecord,
    *,
    window_minutes: int,
    threshold: int,
) -> tuple[str, bool, bool, str, CorrelationResult]:
    priority = alert_priority(alert.severity)
    now = datetime.now(timezone.utc).isoformat()

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")

        duplicate = conn.execute(
            "SELECT case_id FROM case_alerts WHERE alert_id=? LIMIT 1",
            (alert.alert_id,),
        ).fetchone()
        if duplicate:
            conn.commit()
            return (
                duplicate["case_id"],
                False,
                True,
                priority,
                CorrelationResult(
                    True,
                    100,
                    [CorrelationReason(
                        "duplicate-alert-id",
                        100,
                        f"Alert {alert.alert_id} was already ingested",
                    )],
                ),
            )

        rows = _sqlite_candidate_rows(
            conn,
            alert,
            window_minutes=window_minutes,
        )
        candidates = [
            (row["case_id"], _row_to_alert(row))
            for row in rows
        ]
        case_id, correlation = _best_match(
            alert,
            candidates,
            window_minutes=window_minutes,
            threshold=threshold,
        )
        created = case_id is None
        if created:
            case_id = case_id_for_alert(alert)
            conn.execute(
                """
                INSERT INTO cases(
                  case_id,state,priority,owner,opened_at,updated_at,
                  source,title,acknowledged_at,evidence_path
                ) VALUES(?,?,?,?,?,?,?,?,NULL,NULL)
                ON CONFLICT(case_id) DO NOTHING
                """,
                (
                    case_id,
                    "new",
                    priority,
                    None,
                    now,
                    now,
                    alert.source,
                    alert.title,
                ),
            )

        conn.execute(
            """
            INSERT INTO alerts(
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

        link_result = _root_result() if created else correlation
        conn.execute(
            """
            INSERT INTO case_alerts(
              case_id,alert_id,correlation_score,correlation_reasons,linked_at
            ) VALUES(?,?,?,?,?)
            """,
            (
                case_id,
                alert.alert_id,
                link_result.score,
                json.dumps([asdict(item) for item in link_result.reasons]),
                now,
            ),
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
            priority = upgraded

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
                        "created_case": created,
                        "correlation_score": (
                            0 if created else correlation.score
                        ),
                        "correlation_reasons": (
                            [asdict(item) for item in _new_case_result().reasons]
                            if created
                            else [asdict(item) for item in correlation.reasons]
                        ),
                    },
                    ensure_ascii=False,
                )[:5000],
                now,
            ),
        )
        conn.commit()

    return (
        case_id,
        created,
        False,
        priority,
        _new_case_result() if created else correlation,
    )


def _pg_decide_and_store(
    dsn: str,
    alert: AlertRecord,
    *,
    window_minutes: int,
    threshold: int,
) -> tuple[str, bool, bool, str, CorrelationResult]:
    initialize_postgres(dsn)
    priority = alert_priority(alert.severity)
    now = datetime.now(timezone.utc)

    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            lock_keys = _correlation_lock_keys(alert)
            if not lock_keys:
                lock_keys = [f"source:{alert.source.lower()}"]
            for key in lock_keys:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"socmind-alert:{key}",),
                )

            cur.execute(
                "SELECT case_id FROM case_alerts WHERE alert_id=%s LIMIT 1",
                (alert.alert_id,),
            )
            duplicate = cur.fetchone()
            if duplicate:
                conn.commit()
                return (
                    duplicate["case_id"],
                    False,
                    True,
                    priority,
                    CorrelationResult(
                        True,
                        100,
                        [CorrelationReason(
                            "duplicate-alert-id",
                            100,
                            f"Alert {alert.alert_id} was already ingested",
                        )],
                    ),
                )

            rows = _pg_candidate_rows(
                cur,
                alert,
                window_minutes=window_minutes,
            )
            candidates = [
                (row["case_id"], _row_to_alert(row))
                for row in rows
            ]
            case_id, correlation = _best_match(
                alert,
                candidates,
                window_minutes=window_minutes,
                threshold=threshold,
            )
            created = case_id is None
            if created:
                case_id = case_id_for_alert(alert)
                cur.execute(
                    """
                    INSERT INTO cases(
                      case_id,state,priority,owner,opened_at,updated_at,
                      source,title,acknowledged_at,evidence_path
                    ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,NULL,NULL)
                    ON CONFLICT(case_id) DO NOTHING
                    """,
                    (
                        case_id,
                        "new",
                        priority,
                        None,
                        now,
                        now,
                        alert.source,
                        alert.title,
                    ),
                )

            cur.execute(
                """
                INSERT INTO alerts(
                  alert_id,source,timestamp,title,severity,priority,host,"user",process,
                  src_ip,dst_ip,technique,rule_id,fingerprint,raw_reference,created_at
                ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
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

            link_result = _root_result() if created else correlation
            cur.execute(
                """
                INSERT INTO case_alerts(
                  case_id,alert_id,correlation_score,correlation_reasons,linked_at
                ) VALUES(%s,%s,%s,%s::jsonb,%s)
                """,
                (
                    case_id,
                    alert.alert_id,
                    link_result.score,
                    json.dumps([asdict(item) for item in link_result.reasons]),
                    now,
                ),
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
                priority = upgraded

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
                            "created_case": created,
                            "correlation_score": (
                                0 if created else correlation.score
                            ),
                            "correlation_reasons": (
                                [asdict(item) for item in _new_case_result().reasons]
                                if created
                                else [asdict(item) for item in correlation.reasons]
                            ),
                        },
                        ensure_ascii=False,
                    )[:5000],
                    now,
                ),
            )
        conn.commit()

    return (
        case_id,
        created,
        False,
        priority,
        _new_case_result() if created else correlation,
    )


def orchestrate_alert_sqlite(
    db_path: str | Path,
    alert: AlertRecord,
    events: list[Event],
    *,
    evidence_dir: str | Path,
    correlation_window_minutes: int = 15,
    correlation_threshold: int = 55,
    evidence_before_minutes: int = 15,
    evidence_after_minutes: int = 15,
) -> OrchestrationResult:
    case_id, created, duplicate, priority, correlation = (
        _sqlite_decide_and_store(
            db_path,
            alert,
            window_minutes=correlation_window_minutes,
            threshold=correlation_threshold,
        )
    )

    evidence_path = Path(evidence_dir) / f"{case_id}.jsonl"
    if duplicate:
        count = len(_load_existing_evidence(evidence_path))
    else:
        window = collect_evidence_window(
            alert,
            events,
            before_minutes=evidence_before_minutes,
            after_minutes=evidence_after_minutes,
        )
        count = _merge_evidence(
            evidence_path,
            window.events,
            case_id=case_id,
            source=alert.source,
        )
        with connect(db_path) as conn:
            conn.execute(
                "UPDATE cases SET evidence_path=? WHERE case_id=?",
                (str(evidence_path.resolve()), case_id),
            )
            conn.commit()

    return OrchestrationResult(
        case_id,
        created,
        duplicate,
        priority,
        correlation.score,
        [asdict(item) for item in correlation.reasons],
        count,
        str(evidence_path.resolve()),
    )


def orchestrate_alert_postgres(
    dsn: str,
    alert: AlertRecord,
    events: list[Event],
    *,
    evidence_dir: str | Path,
    correlation_window_minutes: int = 15,
    correlation_threshold: int = 55,
    evidence_before_minutes: int = 15,
    evidence_after_minutes: int = 15,
) -> OrchestrationResult:
    case_id, created, duplicate, priority, correlation = (
        _pg_decide_and_store(
            dsn,
            alert,
            window_minutes=correlation_window_minutes,
            threshold=correlation_threshold,
        )
    )

    evidence_path = Path(evidence_dir) / f"{case_id}.jsonl"
    if duplicate:
        count = len(_load_existing_evidence(evidence_path))
    else:
        window = collect_evidence_window(
            alert,
            events,
            before_minutes=evidence_before_minutes,
            after_minutes=evidence_after_minutes,
        )
        count = _merge_evidence(
            evidence_path,
            window.events,
            case_id=case_id,
            source=alert.source,
        )
        with _connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE cases SET evidence_path=%s WHERE case_id=%s",
                    (str(evidence_path.resolve()), case_id),
                )
            conn.commit()

    return OrchestrationResult(
        case_id,
        created,
        duplicate,
        priority,
        correlation.score,
        [asdict(item) for item in correlation.reasons],
        count,
        str(evidence_path.resolve()),
    )
