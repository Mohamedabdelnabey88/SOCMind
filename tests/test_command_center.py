from datetime import datetime, timezone, timedelta

from socmind.case_workflow import CaseState
from socmind.command_center import acknowledge_case, command_center_snapshot, upsert_case


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
