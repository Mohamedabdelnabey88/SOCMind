from __future__ import annotations

from dataclasses import asdict, dataclass

from .engine import analyze
from .hypothesis import generate_hypotheses
from .models import Event


@dataclass(frozen=True, slots=True)
class EvidencePoint:
    kind: str
    statement: str
    event_index: int | None = None


@dataclass(frozen=True, slots=True)
class HypothesisReview:
    hypothesis: str
    confidence: int
    supporting: list[EvidencePoint]
    contradicting: list[EvidencePoint]
    unresolved: list[str]


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "approved", "success", "trusted"}


def _context_points(events: list[Event]) -> list[EvidencePoint]:
    points: list[EvidencePoint] = []
    for index, event in enumerate(events, 1):
        data = event.data or {}

        mfa = str(data.get("mfa_result", "")).lower()
        device = str(data.get("device_trust", "")).lower()
        if mfa in {"success", "passed"} and device in {"trusted", "compliant", "managed"}:
            points.append(
                EvidencePoint(
                    "identity-context",
                    "Successful MFA from a trusted/managed device weakens an account-compromise hypothesis.",
                    index,
                )
            )

        if _truthy(data.get("change_approved")) or data.get("change_ticket"):
            points.append(
                EvidencePoint(
                    "change-context",
                    "Approved change-control context can explain execution or persistence activity.",
                    index,
                )
            )

        if _truthy(data.get("admin_approved")):
            points.append(
                EvidencePoint(
                    "admin-context",
                    "Administrative approval is recorded for this activity.",
                    index,
                )
            )

        signature = str(data.get("signature_status", "")).lower()
        if signature in {"trusted", "signed", "valid"}:
            points.append(
                EvidencePoint(
                    "binary-context",
                    "Trusted code-signing context weakens, but does not eliminate, a malicious-execution hypothesis.",
                    index,
                )
            )

        if _truthy(data.get("known_scanner")) or _truthy(data.get("authorized_scanner")):
            points.append(
                EvidencePoint(
                    "network-context",
                    "The source is marked as an authorized scanner, which can explain repeated authentication attempts.",
                    index,
                )
            )
    return points


def review_hypotheses(events: list[Event]) -> list[HypothesisReview]:
    findings = analyze(events)
    hypotheses = generate_hypotheses(findings)
    context = _context_points(events)

    reviews: list[HypothesisReview] = []
    for hypothesis in hypotheses:
        supporting = [
            EvidencePoint("support", statement)
            for statement in hypothesis.supporting
        ]

        contradicting = [
            EvidencePoint("validation-gap", statement)
            for statement in hypothesis.contradicting
        ]

        name = hypothesis.name.lower()
        for point in context:
            if "account compromise" in name and point.kind in {
                "identity-context",
                "network-context",
            }:
                contradicting.append(point)
            elif "malicious execution" in name and point.kind in {
                "change-context",
                "admin-context",
                "binary-context",
            }:
                contradicting.append(point)
            elif "persistence" in name and point.kind in {
                "change-context",
                "admin-context",
            }:
                contradicting.append(point)

        unresolved: list[str] = []
        if "account compromise" in name:
            unresolved += [
                "Validate IdP/MFA session details.",
                "Compare source IP/device with user baseline.",
            ]
        if "malicious execution" in name:
            unresolved += [
                "Validate process ancestry and signer reputation.",
                "Check approved automation/change context.",
            ]
        if "persistence" in name:
            unresolved += [
                "Confirm whether the persistence mechanism is approved.",
                "Validate creator identity and change ticket.",
            ]

        reviews.append(
            HypothesisReview(
                hypothesis=hypothesis.name,
                confidence=hypothesis.confidence,
                supporting=supporting,
                contradicting=contradicting,
                unresolved=unresolved,
            )
        )
    return reviews


def contradiction_payload(events: list[Event]) -> dict:
    reviews = review_hypotheses(events)
    return {
        "hypotheses": [
            {
                "hypothesis": review.hypothesis,
                "confidence": review.confidence,
                "supporting": [asdict(item) for item in review.supporting],
                "contradicting": [asdict(item) for item in review.contradicting],
                "unresolved": review.unresolved,
            }
            for review in reviews
        ],
        "summary": {
            "hypotheses": len(reviews),
            "supporting_points": sum(len(item.supporting) for item in reviews),
            "contradicting_points": sum(len(item.contradicting) for item in reviews),
            "unresolved_questions": sum(len(item.unresolved) for item in reviews),
        },
    }


def render_contradictions(events: list[Event]) -> str:
    payload = contradiction_payload(events)
    lines = [
        "SOCMind Evidence Contradiction Review",
        "====================================",
    ]
    for review in payload["hypotheses"]:
        lines += [
            "",
            f"{review['hypothesis']} | confidence={review['confidence']}%",
            "  Supporting:",
        ]
        lines += [
            f"    + {item['statement']}"
            for item in review["supporting"]
        ] or ["    - none"]
        lines.append("  Contradicting / alternative context:")
        lines += [
            f"    - {item['statement']}"
            for item in review["contradicting"]
        ] or ["    - none observed"]
        lines.append("  Unresolved:")
        lines += [f"    ? {item}" for item in review["unresolved"]] or ["    - none"]
    return "\n".join(lines)
