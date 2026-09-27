from socmind.models import Finding
from socmind.triage import triage


def finding(title: str, score: int) -> Finding:
    return Finding(title, "high", score, ["test"], ["T0000"], [])


def test_high_score_is_p1():
    decision = triage(finding("Suspicious PowerShell execution", 85))
    assert decision.priority == "P1"
    assert "Tier 2" in decision.escalation
    assert any("parent" in step.lower() for step in decision.next_steps)


def test_medium_score_is_p2():
    decision = triage(finding("Repeated SSH failures followed by successful authentication", 65))
    assert decision.priority == "P2"
    assert any("MFA" in step for step in decision.next_steps)
