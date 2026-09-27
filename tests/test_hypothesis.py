from socmind.hypothesis import generate_hypotheses
from socmind.models import Finding


def f(title: str, score: int = 70):
    return Finding(title, "high", score, ["reason"], ["T0000"], [])


def test_compromise_hypothesis_strengthens_with_execution_and_persistence():
    hypotheses = generate_hypotheses([
        f("Repeated failed logons followed by successful authentication"),
        f("Suspicious PowerShell execution"),
        f("Persistence-related Windows system change"),
    ])
    account = next(h for h in hypotheses if h.name == "Potential account compromise")
    assert account.confidence == 85
    assert len(account.supporting) == 3
