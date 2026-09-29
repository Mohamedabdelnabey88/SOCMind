from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .adapters.elastic import parse_elastic_hits
from .command_center import case_detail, connect
from .enterprise_command_center import _connect, case_detail_pg
from .integrations import ElasticClient
from .models import Event
from .orchestration import _merge_evidence
from .postgres_store import initialize_postgres


@dataclass(frozen=True, slots=True)
class CollectionPlan:
    case_id: str
    provider: str
    source_ref: str
    window_start: str
    window_end: str
    query: dict
    evidence_path: str


@dataclass(frozen=True, slots=True)
class CollectionResult:
    collection_id: str
    case_id: str
    provider: str
    source_ref: str
    status: str
    fetched_events: int
    evidence_events: int
    evidence_path: str
    window_start: str
    window_end: str
    error: str | None = None


def _parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _unique(values) -> list[str]:
    return sorted({str(value) for value in values if value not in (None, "")})


def _process_basename(value: str) -> str:
    return str(value).replace("\\", "/").rsplit("/", 1)[-1]


def build_collection_plan(
    case: dict,
    alerts: list[dict],
    *,
    provider: str,
    source_ref: str,
    evidence_dir: str | Path,
    before_minutes: int = 15,
    after_minutes: int = 15,
) -> CollectionPlan:
    if not alerts:
        raise ValueError("Case has no linked alerts to derive evidence context")

    timestamps = [_parse_ts(item["timestamp"]) for item in alerts]
    start = min(timestamps) - timedelta(minutes=max(0, int(before_minutes)))
    end = max(timestamps) + timedelta(minutes=max(0, int(after_minutes)))

    should: list[dict] = []
    field_values = {
        "host.name": _unique(item.get("host") for item in alerts),
        "user.name": _unique(item.get("user") for item in alerts),
        "process.name": _unique(
            _process_basename(str(item.get("process")))
            for item in alerts
            if item.get("process")
        ),
        "process.executable": _unique(item.get("process") for item in alerts),
        "source.ip": _unique(item.get("src_ip") for item in alerts),
        "destination.ip": _unique(item.get("dst_ip") for item in alerts),
    }
    for field, values in field_values.items():
        if len(values) == 1:
            should.append({"term": {field: values[0]}})
        elif values:
            should.append({"terms": {field: values}})

    bool_query: dict = {
        "filter": [
            {
                "range": {
                    "@timestamp": {
                        "gte": start.isoformat().replace("+00:00", "Z"),
                        "lte": end.isoformat().replace("+00:00", "Z"),
                    }
                }
            }
        ]
    }
    if should:
        bool_query["should"] = should
        bool_query["minimum_should_match"] = 1

    case_id = str(case["case_id"])
    evidence_path = Path(evidence_dir) / f"{case_id}.jsonl"
    return CollectionPlan(
        case_id=case_id,
        provider=provider,
        source_ref=source_ref,
        window_start=start.isoformat(),
        window_end=end.isoformat(),
        query={"bool": bool_query},
        evidence_path=str(evidence_path.resolve()),
    )


def _start_sqlite_collection(db_path: str | Path, plan: CollectionPlan) -> str:
    collection_id = f"COL-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO evidence_collections(
              collection_id,case_id,provider,source_ref,window_start,window_end,
              query_json,status,event_count,error,started_at,completed_at
            ) VALUES(?,?,?,?,?,?,?,'running',0,NULL,?,NULL)
            """,
            (
                collection_id,
                plan.case_id,
                plan.provider,
                plan.source_ref,
                plan.window_start,
                plan.window_end,
                json.dumps(plan.query, ensure_ascii=False),
                now,
            ),
        )
        conn.commit()
    return collection_id


def _finish_sqlite_collection(
    db_path: str | Path,
    collection_id: str,
    *,
    case_id: str,
    status: str,
    event_count: int,
    evidence_path: str,
    error: str | None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        conn.execute(
            """
            UPDATE evidence_collections
            SET status=?,event_count=?,error=?,completed_at=?
            WHERE collection_id=?
            """,
            (status, event_count, error, now, collection_id),
        )
        if status == "completed":
            conn.execute(
                "UPDATE cases SET evidence_path=?,updated_at=? WHERE case_id=?",
                (evidence_path, now, case_id),
            )
        conn.execute(
            """
            INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
            VALUES(?,?,?,?,?)
            """,
            (
                case_id,
                "socmind-evidence-collector",
                "evidence-collected" if status == "completed" else "evidence-collection-failed",
                json.dumps(
                    {
                        "collection_id": collection_id,
                        "status": status,
                        "event_count": event_count,
                        "error": error,
                    },
                    ensure_ascii=False,
                )[:5000],
                now,
            ),
        )
        conn.commit()


def _start_pg_collection(dsn: str, plan: CollectionPlan) -> str:
    initialize_postgres(dsn)
    collection_id = f"COL-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(timezone.utc)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO evidence_collections(
                  collection_id,case_id,provider,source_ref,window_start,window_end,
                  query_json,status,event_count,error,started_at,completed_at
                ) VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb,'running',0,NULL,%s,NULL)
                """,
                (
                    collection_id,
                    plan.case_id,
                    plan.provider,
                    plan.source_ref,
                    plan.window_start,
                    plan.window_end,
                    json.dumps(plan.query, ensure_ascii=False),
                    now,
                ),
            )
        conn.commit()
    return collection_id


def _finish_pg_collection(
    dsn: str,
    collection_id: str,
    *,
    case_id: str,
    status: str,
    event_count: int,
    evidence_path: str,
    error: str | None,
) -> None:
    now = datetime.now(timezone.utc)
    with _connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE evidence_collections
                SET status=%s,event_count=%s,error=%s,completed_at=%s
                WHERE collection_id=%s
                """,
                (status, event_count, error, now, collection_id),
            )
            if status == "completed":
                cur.execute(
                    "UPDATE cases SET evidence_path=%s,updated_at=%s WHERE case_id=%s",
                    (evidence_path, now, case_id),
                )
            cur.execute(
                """
                INSERT INTO case_audit(case_id,actor,action,detail,timestamp)
                VALUES(%s,%s,%s,%s,%s)
                """,
                (
                    case_id,
                    "socmind-evidence-collector",
                    "evidence-collected" if status == "completed" else "evidence-collection-failed",
                    json.dumps(
                        {
                            "collection_id": collection_id,
                            "status": status,
                            "event_count": event_count,
                            "error": error,
                        },
                        ensure_ascii=False,
                    )[:5000],
                    now,
                ),
            )
        conn.commit()


def collect_case_evidence_sqlite(
    db_path: str | Path,
    case_id: str,
    client: ElasticClient,
    *,
    provider: str,
    index: str,
    evidence_dir: str | Path,
    before_minutes: int = 15,
    after_minutes: int = 15,
    max_events: int = 2000,
) -> CollectionResult:
    detail = case_detail(db_path, case_id)
    plan = build_collection_plan(
        detail["case"],
        detail.get("alerts", []),
        provider=provider,
        source_ref=index,
        evidence_dir=evidence_dir,
        before_minutes=before_minutes,
        after_minutes=after_minutes,
    )
    collection_id = _start_sqlite_collection(db_path, plan)
    try:
        response = client.search(
            index,
            query=plan.query,
            size=max(1, min(int(max_events), 10000)),
            sort=[{"@timestamp": {"order": "asc"}}],
        )
        hits = response.get("hits", {}).get("hits", [])
        events: list[Event] = parse_elastic_hits(hits)
        evidence_count = _merge_evidence(Path(plan.evidence_path), events)
        _finish_sqlite_collection(
            db_path,
            collection_id,
            case_id=case_id,
            status="completed",
            event_count=len(events),
            evidence_path=plan.evidence_path,
            error=None,
        )
        return CollectionResult(
            collection_id,
            case_id,
            provider,
            index,
            "completed",
            len(events),
            evidence_count,
            plan.evidence_path,
            plan.window_start,
            plan.window_end,
        )
    except Exception as exc:
        _finish_sqlite_collection(
            db_path,
            collection_id,
            case_id=case_id,
            status="failed",
            event_count=0,
            evidence_path=plan.evidence_path,
            error=str(exc)[:1000],
        )
        raise


def collect_case_evidence_postgres(
    dsn: str,
    case_id: str,
    client: ElasticClient,
    *,
    provider: str,
    index: str,
    evidence_dir: str | Path,
    before_minutes: int = 15,
    after_minutes: int = 15,
    max_events: int = 2000,
) -> CollectionResult:
    initialize_postgres(dsn)
    detail = case_detail_pg(dsn, case_id)
    plan = build_collection_plan(
        detail["case"],
        detail.get("alerts", []),
        provider=provider,
        source_ref=index,
        evidence_dir=evidence_dir,
        before_minutes=before_minutes,
        after_minutes=after_minutes,
    )
    collection_id = _start_pg_collection(dsn, plan)
    try:
        response = client.search(
            index,
            query=plan.query,
            size=max(1, min(int(max_events), 10000)),
            sort=[{"@timestamp": {"order": "asc"}}],
        )
        hits = response.get("hits", {}).get("hits", [])
        events: list[Event] = parse_elastic_hits(hits)
        evidence_count = _merge_evidence(Path(plan.evidence_path), events)
        _finish_pg_collection(
            dsn,
            collection_id,
            case_id=case_id,
            status="completed",
            event_count=len(events),
            evidence_path=plan.evidence_path,
            error=None,
        )
        return CollectionResult(
            collection_id,
            case_id,
            provider,
            index,
            "completed",
            len(events),
            evidence_count,
            plan.evidence_path,
            plan.window_start,
            plan.window_end,
        )
    except Exception as exc:
        _finish_pg_collection(
            dsn,
            collection_id,
            case_id=case_id,
            status="failed",
            event_count=0,
            evidence_path=plan.evidence_path,
            error=str(exc)[:1000],
        )
        raise


def collection_payload(result: CollectionResult) -> dict:
    return asdict(result)
