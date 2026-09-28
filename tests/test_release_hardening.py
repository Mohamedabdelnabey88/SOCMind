from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import add_case_note, connect, upsert_case
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_web_security_headers():
    app = create_app(ROOT / "examples/attack_chain.jsonl")
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_sqlite_reliability_pragmas(tmp_path):
    db = tmp_path / "soc.db"
    with connect(db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 10000
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_note_size_bound(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(db, new_case("INC-001"))
    with pytest.raises(ValueError):
        add_case_note(
            db,
            "INC-001",
            author="analyst",
            text="x" * 5001,
        )
