from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(slots=True)
class Hypothesis:
    name: str
    confidence: int
    supporting: list[str]
    contradicting: list[str]


def generate_hypotheses(findings: list[Finding]) -> list[Hypothesis]:
    titles = " ".join(f.title.lower() for f in findings)
    hypotheses: list[Hypothesis] = []

    auth_signal = any(
        token in titles for token in ("failed logons", "ssh failures", "successful authentication")
    )
    execution_signal = "powershell" in titles or "privileged linux" in titles
    persistence_signal = "persistence" in titles

    if auth_signal:
        support = ["Authentication failures were followed by a successful session."]
        confidence = 45
        if execution_signal:
            support.append("Suspicious post-authentication execution was observed.")
            confidence += 20
        if persistence_signal:
            support.append("Persistence-related activity followed on the same investigation path.")
            confidence += 20
        hypotheses.append(
            Hypothesis(
                "Potential account compromise",
                min(confidence, 95),
                support,
                [
                    "A successful authentication can still be legitimate.",
                    "Identity-provider and MFA context are required for confirmation.",
                ],
            )
        )

    if execution_signal:
        support = ["Execution behavior matched a high-interest analyst pattern."]
        confidence = 50 + (20 if persistence_signal else 0)
        hypotheses.append(
            Hypothesis(
                "Potential malicious execution",
                min(confidence, 95),
                support,
                [
                    "Administrative scripts can resemble malicious behavior.",
                    "Process ancestry and change-control context should be validated.",
                ],
            )
        )

    if persistence_signal:
        hypotheses.append(
            Hypothesis(
                "Potential persistence establishment",
                70,
                ["A persistence-related task or service change was detected."],
                ["Legitimate software deployment can create equivalent artifacts."],
            )
        )

    return hypotheses
