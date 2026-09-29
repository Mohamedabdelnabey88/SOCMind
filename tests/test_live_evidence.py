from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from socmind.command_center import case_detail
from socmind.io import load_jsonl
from socmind.live_evidence import (
    build_collection_plan,
    collect_case_evidence_sqlite,
)
from socmind.orchestration import orchestrate_alert_sqlite
from socmind.production_ops import AlertRecord


ROOT = Path(__file__).resolve().parents[1]


class FakeElastic:
    def __init__(self, hits=None, error=None):
        self.hits = hits or []
        self.error = error
        self.calls = []

    def search(self, index, *, query=None, size=100, sort=None):
        self.calls.append({
            "index": index,
            "query": query,
            "size": size,
            "sort": sort,
        })
        if self.error:
            raise self.error
        return {"hits": {"hits": self.hits}}


def _case_with_alert(tmp_path):
    db = tmp_path / "soc.db"
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    base = events[0]
    alert = AlertRecord(
        "LIVE-ALERT-001",
        "elastic",
        base.timestamp,
        "Live evidence test",
        12,
        base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="LIVE-1",
    )
    result = orchestrate_alert_sqlite(
        db,
        alert,
        events,
        evidence_dir=tmp_path / "initial",
    )
    return db, result.case_id, events, alert


def test_collection_plan_uses_case_alert_context(tmp_path):
    db, case_id, _, _ = _case_with_alert(tmp_path)
    detail = case_detail(db, case_id)
    plan = build_collection_plan(
        detail["case"],
        detail["alerts"],
        provider="elastic",
        source_ref="logs-*",
        evidence_dir=tmp_path / "evidence",
    )
    bool_query = plan.query["bool"]
    assert bool_query["filter"][0]["range"]["@timestamp"]
    assert bool_query["should"]
    assert bool_query["minimum_should_match"] == 1
    serialized = str(bool_query["should"])
    assert detail["alerts"][0]["host"] in serialized


def test_live_collection_merges_evidence_and_journals_success(tmp_path):
    db, case_id, events, alert = _case_with_alert(tmp_path)
    event = events[0]
    hit = {
        "_id": "live-hit-1",
        "_index": "logs-windows",
        "_source": {
            "@timestamp": (alert.timestamp + timedelta(seconds=30)).isoformat(),
            "event": {"code": event.event_id},
            "host": {"name": event.host},
            "user": {"name": event.user},
            "source": {"ip": event.src_ip},
            "process": {"name": event.process or "powershell.exe"},
        },
    }
    client = FakeElastic([hit])
    result = collect_case_evidence_sqlite(
        db,
        case_id,
        client,
        provider="elastic",
        index="logs-*",
        evidence_dir=tmp_path / "live-evidence",
    )

    assert result.status == "completed"
    assert result.fetched_events == 1
    assert result.evidence_events == 1
    assert Path(result.evidence_path).is_file()
    assert client.calls[0]["index"] == "logs-*"
    assert client.calls[0]["sort"]

    detail = case_detail(db, case_id)
    assert detail["case"]["evidence_path"] == result.evidence_path
    assert detail["evidence_collections"][0]["status"] == "completed"
    assert detail["evidence_collections"][0]["event_count"] == 1
    assert detail["evidence_collections"][0]["query"]["bool"]
    assert any(
        item["action"] == "evidence-collected"
        for item in detail["audit"]
    )


def test_live_collection_records_provider_failure(tmp_path):
    db, case_id, _, _ = _case_with_alert(tmp_path)
    client = FakeElastic(error=RuntimeError("provider unavailable"))

    with pytest.raises(RuntimeError, match="provider unavailable"):
        collect_case_evidence_sqlite(
            db,
            case_id,
            client,
            provider="elastic",
            index="logs-*",
            evidence_dir=tmp_path / "failed-evidence",
        )

    detail = case_detail(db, case_id)
    collection = detail["evidence_collections"][0]
    assert collection["status"] == "failed"
    assert collection["event_count"] == 0
    assert "provider unavailable" in collection["error"]
    assert any(
        item["action"] == "evidence-collection-failed"
        for item in detail["audit"]
    )
