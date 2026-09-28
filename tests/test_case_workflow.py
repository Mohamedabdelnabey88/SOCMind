from datetime import datetime, timezone, timedelta

import pytest

from socmind.case_workflow import assign, new_case, transition
from socmind.sla import evaluate_sla


def test_case_state_machine_and_assignment():
    case = new_case("INC-001", priority="P1")
    assign(case, "tier2-analyst")
    transition(case, "triage")
    transition(case, "investigating")
    assert case.owner == "tier2-analyst"
    assert case.state == "investigating"


def test_invalid_case_transition_fails():
    case = new_case("INC-001")
    with pytest.raises(ValueError):
        transition(case, "resolved")


def test_sla_breach_calculation():
    opened = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    status = evaluate_sla(opened, priority="P1")
    assert status.breached
    assert status.target_minutes == 15
