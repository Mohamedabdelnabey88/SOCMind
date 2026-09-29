import sqlite3
from datetime import datetime, timezone, timedelta

from socmind.case_workflow import CaseState
from socmind.command_center import (
    acknowledge_case,
    command_center_snapshot,
    connect,
    transition_case,
    upsert_case,
)


def make_case(case_id, priority, state, owner, opened_delta=0, updated_delta=0):
    now = datetime.now(timezone.utc)
    return CaseState(
        case_id=case_id,
        state=state,
        owner=owner,
        priority=priority,
        opened_at=(now - timedelta(minutes=opened_delta)).isoformat(),
        updated_at=(now - timedelta(minutes=updated_delta)).isoformat(),
    )


def test_command_center_tracks_queue_sla_and_workload(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(db, make_case("INC-P1", "P1", "investigating", "alice", opened_delta=30))
    upsert_case(db, make_case("INC-P2", "P2", "triage", None, opened_delta=5))
    upsert_case(db, make_case("INC-DONE", "P3", "resolved", "alice", opened_delta=60, updated_delta=0))

    acknowledge_case(db, "INC-P2")
    snap = command_center_snapshot(db)
    assert snap["summary"]["total"] == 3
    assert snap["summary"]["active"] == 2
    assert snap["summary"]["p1_active"] == 1
    assert snap["summary"]["sla_breached"] == 1
    assert snap["summary"]["unassigned"] == 1
    assert snap["summary"]["mtta_minutes"] is not None
    owners = {x["owner"]: x["active_cases"] for x in snap["workload"]}
    assert owners["alice"] == 1
    assert owners["Unassigned"] == 1


def test_waiting_state_pauses_sla_and_resume_accumulates_pause(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(db, make_case("INC-WAIT", "P1", "triage", "alice", opened_delta=30))

    transition_case(db, "INC-WAIT", "waiting-for-evidence", actor="alice")
    paused = command_center_snapshot(db)
    item = next(x for x in paused["queue"] if x["case_id"] == "INC-WAIT")
    assert item["state"] == "waiting-for-evidence"
    assert item["sla"]["paused"] is True

    with connect(db) as conn:
        row = conn.execute(
            "SELECT sla_paused_at FROM cases WHERE case_id=?",
            ("INC-WAIT",),
        ).fetchone()
        artificial_start = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).isoformat()
        conn.execute(
            "UPDATE cases SET sla_paused_at=? WHERE case_id=?",
            (artificial_start, "INC-WAIT"),
        )
        conn.commit()

    transition_case(db, "INC-WAIT", "investigating", actor="alice")
    with connect(db) as conn:
        row = conn.execute(
            "SELECT sla_paused_at,sla_paused_seconds FROM cases WHERE case_id=?",
            ("INC-WAIT",),
        ).fetchone()
    assert row["sla_paused_at"] is None
    assert row["sla_paused_seconds"] >= 9 * 60

    resumed = command_center_snapshot(db)
    item = next(x for x in resumed["queue"] if x["case_id"] == "INC-WAIT")
    assert item["sla"]["paused"] is False
    assert item["sla"]["paused_minutes"] >= 9


def test_state_history_records_actor_timestamp_and_reason(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(db, make_case("INC-HISTORY", "P2", "new", "alice"))

    transition_case(
        db,
        "INC-HISTORY",
        "triage",
        actor="alice",
        reason="Initial validation started",
    )

    from socmind.command_center import case_detail
    detail = case_detail(db, "INC-HISTORY")
    history = detail["state_history"]
    assert len(history) == 1
    assert history[0]["actor"] == "alice"
    assert history[0]["timestamp"]
    assert history[0]["from_state"] == "new"
    assert history[0]["to_state"] == "triage"
    assert history[0]["reason"] == "Initial validation started"


def test_connect_migrates_existing_sqlite_cases_table(tmp_path):
    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            CREATE TABLE cases (
                case_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                priority TEXT NOT NULL,
                owner TEXT,
                opened_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                source TEXT,
                title TEXT,
                acknowledged_at TEXT,
                evidence_path TEXT
            )
            """
        )
        conn.commit()

    with connect(db) as conn:
        columns = {
            row[1]: row
            for row in conn.execute("PRAGMA table_info(cases)").fetchall()
        }

    assert "sla_paused_at" in columns
    assert "sla_paused_seconds" in columns
