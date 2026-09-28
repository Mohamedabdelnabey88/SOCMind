from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from socmind.audit_chain import append_record, verify_chain
from socmind.case_workflow import new_case
from socmind.command_center import transition_case, upsert_case
from socmind.http_client import HTTPClientError, JSONHTTPClient


def test_http_client_rejects_non_http_schemes():
    client = JSONHTTPClient()
    with pytest.raises(HTTPClientError, match="Only http"):
        client.request("GET", "file:///etc/passwd")


def test_audit_chain_serializes_concurrent_writers(tmp_path):
    audit = tmp_path / "audit.jsonl"

    def write(index: int):
        return append_record(
            audit,
            case_id="INC-CONCURRENT",
            actor=f"analyst-{index}",
            action="note",
            detail=f"entry-{index}",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(write, range(24)))

    assert sorted(record.sequence for record in records) == list(range(1, 25))
    assert verify_chain(audit) == (True, 24, None)


def test_sqlite_transition_is_serialized(tmp_path):
    db = tmp_path / "soc.db"
    case = new_case("INC-RACE", priority="P1")
    upsert_case(db, case)
    transition_case(db, "INC-RACE", "triage")

    def move():
        try:
            transition_case(db, "INC-RACE", "investigating")
            return "ok"
        except ValueError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: move(), range(2)))

    assert sorted(results) == ["ok", "rejected"]
