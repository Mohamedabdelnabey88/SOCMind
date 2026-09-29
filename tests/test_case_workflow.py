import json
from datetime import datetime, timezone, timedelta

import pytest

from socmind.case_workflow import CaseState, assign, load_case, new_case, transition
from socmind.sla import evaluate_sla


def test_case_state_machine_and_assignment():
    case = new_case("INC-001", priority="P1")
    assign(case, "tier2-analyst")
    transition(case, "triage")
    transition(case, "investigating")
    assert case.owner == "tier2-analyst"
    assert case.state == "investigating"


def test_advanced_case_lifecycle_wait_monitor_and_resume():
    base = datetime(2026, 9, 29, 0, 0, tzinfo=timezone.utc)
    case = CaseState(
        "INC-LIFE",
        "triage",
        "analyst",
        "P1",
        base.isoformat(),
        base.isoformat(),
    )

    transition(case, "investigating", now=base + timedelta(minutes=2))
    transition(case, "waiting-for-evidence", now=base + timedelta(minutes=5))
    assert case.sla_paused_at == (base + timedelta(minutes=5)).isoformat()

    transition(case, "waiting-for-user", now=base + timedelta(minutes=15))
    assert case.sla_paused_at == (base + timedelta(minutes=5)).isoformat()
    assert case.sla_paused_seconds == 0

    transition(case, "investigating", now=base + timedelta(minutes=25))
    assert case.sla_paused_at is None
    assert case.sla_paused_seconds == 20 * 60

    transition(case, "contained", now=base + timedelta(minutes=26))
    transition(case, "monitoring", now=base + timedelta(minutes=27))
    transition(case, "resolved", now=base + timedelta(minutes=28))
    assert case.state == "resolved"


def test_invalid_case_transition_fails():
    case = new_case("INC-001")
    with pytest.raises(ValueError):
        transition(case, "resolved")


def test_sla_breach_calculation():
    opened = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    status = evaluate_sla(opened, priority="P1")
    assert status.breached
    assert status.target_minutes == 15


def test_sla_excludes_active_and_accumulated_pause_time():
    base = datetime(2026, 9, 29, 0, 0, tzinfo=timezone.utc)
    status = evaluate_sla(
        base.isoformat(),
        priority="P1",
        now=base + timedelta(minutes=35),
        paused_seconds=10 * 60,
        paused_at=(base + timedelta(minutes=25)).isoformat(),
    )
    assert status.paused is True
    assert status.paused_minutes == 20
    assert status.elapsed_minutes == 15
    assert status.remaining_minutes == 0
    assert status.breached is False


def test_load_case_is_backward_compatible_with_pre_lifecycle_json(tmp_path):
    path = tmp_path / "legacy-case.json"
    path.write_text(
        json.dumps({
            "case_id": "LEGACY-1",
            "state": "triage",
            "owner": None,
            "priority": "P2",
            "opened_at": "2026-09-29T00:00:00+00:00",
            "updated_at": "2026-09-29T00:01:00+00:00",
        }),
        encoding="utf-8",
    )
    case = load_case(path)
    assert case.sla_paused_at is None
    assert case.sla_paused_seconds == 0
