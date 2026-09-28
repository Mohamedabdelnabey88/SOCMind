from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .command_center import list_cases
from .enterprise_command_center import list_cases_pg
from .engine import analyze
from .ioc import extract_iocs
from .io import load_jsonl
from .models import Event


@dataclass(frozen=True, slots=True)
class CaseFingerprint:
    techniques: frozenset[str]
    event_ids: frozenset[str]
    processes: frozenset[str]
    iocs: frozenset[str]
    hosts: frozenset[str]


@dataclass(frozen=True, slots=True)
class SimilarCase:
    case_id: str
    title: str
    score: float
    confidence: str
    matched_dimensions: int
    comparable_dimensions: int
    shared_techniques: list[str]
    shared_event_ids: list[str]
    shared_processes: list[str]
    shared_iocs: list[str]
    explanation: list[str]


WEIGHTS = {
    "techniques": 0.40,
    "event_ids": 0.20,
    "processes": 0.20,
    "iocs": 0.20,
}


def _technique_id(value: str) -> str:
    return value.split()[0].upper()


def fingerprint_case(events: list[Event]) -> CaseFingerprint:
    findings = analyze(events)
    return CaseFingerprint(
        techniques=frozenset(
            _technique_id(value)
            for finding in findings
            for value in finding.techniques
        ),
        event_ids=frozenset(event.event_id for event in events if event.event_id),
        processes=frozenset(
            (event.process or "").lower()
            for event in events
            if event.process
        ),
        iocs=frozenset(ioc.value.lower() for ioc in extract_iocs(events)),
        hosts=frozenset(event.host.lower() for event in events if event.host),
    )


def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _dimension_values(
    fingerprint: CaseFingerprint,
) -> dict[str, frozenset[str]]:
    return {
        "techniques": fingerprint.techniques,
        "event_ids": fingerprint.event_ids,
        "processes": fingerprint.processes,
        "iocs": fingerprint.iocs,
    }


def compare_fingerprints(
    left: CaseFingerprint,
    right: CaseFingerprint,
) -> tuple[float, dict]:
    left_values = _dimension_values(left)
    right_values = _dimension_values(right)

    parts: dict[str, float] = {}
    comparable_weight = 0.0
    weighted_score = 0.0
    for key, weight in WEIGHTS.items():
        left_set = left_values[key]
        right_set = right_values[key]
        if not left_set and not right_set:
            parts[key] = 0.0
            continue
        score = _jaccard(left_set, right_set)
        parts[key] = score
        comparable_weight += weight
        weighted_score += score * weight

    normalized = (
        (weighted_score / comparable_weight) * 100
        if comparable_weight
        else 0.0
    )
    return round(normalized, 1), parts


def _confidence(
    score: float,
    matched_dimensions: int,
    comparable_dimensions: int,
) -> str:
    if comparable_dimensions < 2:
        return "limited"
    if matched_dimensions >= 3 and score >= 70:
        return "high"
    if matched_dimensions >= 2 and score >= 45:
        return "moderate"
    return "limited"


def _find_similar_from_records(
    events: list[Event],
    cases,
    *,
    limit: int = 5,
    exclude_case_id: str | None = None,
) -> list[SimilarCase]:
    current = fingerprint_case(events)
    matches: list[SimilarCase] = []

    for case in cases:
        if exclude_case_id and case.case_id == exclude_case_id:
            continue
        if not case.evidence_path:
            continue
        path = Path(case.evidence_path)
        if not path.is_file():
            continue
        try:
            historical_events = load_jsonl(path)
        except (OSError, ValueError):
            continue

        historical = fingerprint_case(historical_events)
        score, parts = compare_fingerprints(current, historical)
        if score <= 0:
            continue

        shared_techniques = sorted(current.techniques & historical.techniques)
        shared_event_ids = sorted(current.event_ids & historical.event_ids)
        shared_processes = sorted(current.processes & historical.processes)
        shared_iocs = sorted(current.iocs & historical.iocs)

        matched_dimensions = sum(
            bool(values)
            for values in (
                shared_techniques,
                shared_event_ids,
                shared_processes,
                shared_iocs,
            )
        )
        current_values = _dimension_values(current)
        historical_values = _dimension_values(historical)
        comparable_dimensions = sum(
            bool(current_values[key] or historical_values[key])
            for key in WEIGHTS
        )
        confidence = _confidence(
            score,
            matched_dimensions,
            comparable_dimensions,
        )

        explanation: list[str] = []
        if shared_techniques:
            explanation.append(
                "Shared ATT&CK techniques: " + ", ".join(shared_techniques)
            )
        if shared_processes:
            explanation.append(
                "Shared processes: " + ", ".join(shared_processes[:5])
            )
        if shared_iocs:
            explanation.append(
                "Shared IOC values: " + ", ".join(shared_iocs[:5])
            )
        if shared_event_ids:
            explanation.append(
                "Shared event IDs: " + ", ".join(shared_event_ids[:8])
            )
        explanation.append(
            f"Evidence confidence: {confidence} "
            f"({matched_dimensions}/{comparable_dimensions} comparable dimensions overlap)"
        )

        matches.append(
            SimilarCase(
                case_id=case.case_id,
                title=case.title or case.case_id,
                score=score,
                confidence=confidence,
                matched_dimensions=matched_dimensions,
                comparable_dimensions=comparable_dimensions,
                shared_techniques=shared_techniques,
                shared_event_ids=shared_event_ids,
                shared_processes=shared_processes,
                shared_iocs=shared_iocs,
                explanation=explanation,
            )
        )

    return sorted(
        matches,
        key=lambda item: (
            {"high": 0, "moderate": 1, "limited": 2}[item.confidence],
            -item.score,
            -item.matched_dimensions,
            item.case_id,
        ),
    )[:max(1, limit)]


def find_similar_cases(
    events: list[Event],
    database: str | Path,
    *,
    limit: int = 5,
    exclude_case_id: str | None = None,
) -> list[SimilarCase]:
    return _find_similar_from_records(
        events,
        list_cases(database),
        limit=limit,
        exclude_case_id=exclude_case_id,
    )


def find_similar_cases_pg(
    events: list[Event],
    dsn: str,
    *,
    limit: int = 5,
    exclude_case_id: str | None = None,
) -> list[SimilarCase]:
    return _find_similar_from_records(
        events,
        list_cases_pg(dsn),
        limit=limit,
        exclude_case_id=exclude_case_id,
    )


def _similarity_payload(matches: list[SimilarCase]) -> dict:
    return {
        "matches": [asdict(item) for item in matches],
        "summary": {
            "matches": len(matches),
            "highest_score": matches[0].score if matches else 0.0,
            "high_confidence_matches": sum(
                1 for item in matches if item.confidence == "high"
            ),
            "moderate_confidence_matches": sum(
                1 for item in matches if item.confidence == "moderate"
            ),
        },
        "interpretation": (
            "Similarity is normalized evidence/behavior overlap across comparable "
            "dimensions. It is not attribution. Confidence describes evidence "
            "breadth, not probability of a common attacker, campaign, or origin."
        ),
    }


def similarity_payload(
    events: list[Event],
    database: str | Path,
    *,
    limit: int = 5,
    exclude_case_id: str | None = None,
) -> dict:
    return _similarity_payload(
        find_similar_cases(
            events,
            database,
            limit=limit,
            exclude_case_id=exclude_case_id,
        )
    )


def similarity_payload_pg(
    events: list[Event],
    dsn: str,
    *,
    limit: int = 5,
    exclude_case_id: str | None = None,
) -> dict:
    return _similarity_payload(
        find_similar_cases_pg(
            events,
            dsn,
            limit=limit,
            exclude_case_id=exclude_case_id,
        )
    )


def render_similarity(
    events: list[Event],
    database: str | Path,
    *,
    limit: int = 5,
    exclude_case_id: str | None = None,
) -> str:
    payload = similarity_payload(
        events,
        database,
        limit=limit,
        exclude_case_id=exclude_case_id,
    )
    lines = [
        "SOCMind Historical Case Similarity",
        "==================================",
        payload["interpretation"],
        "",
    ]
    if not payload["matches"]:
        lines.append("No comparable evidence-linked historical cases found.")
        return "\n".join(lines)

    for item in payload["matches"]:
        lines.append(
            f"{item['case_id']} | {item['score']}% | "
            f"confidence={item['confidence']} | {item['title']}"
        )
        for reason in item["explanation"]:
            lines.append(f"  - {reason}")
    return "\n".join(lines)
