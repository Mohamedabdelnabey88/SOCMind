from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .command_center import list_cases
from .enterprise_command_center import list_cases_pg
from .engine import analyze
from .ioc import extract_iocs
from .io import load_jsonl
from .models import Event


WEIGHTS = {
    "techniques": 0.40,
    "event_ids": 0.20,
    "processes": 0.20,
    "iocs": 0.20,
}


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
    strength: str
    shared_dimensions: int
    component_scores: dict[str, float]
    shared_techniques: list[str]
    shared_event_ids: list[str]
    shared_processes: list[str]
    shared_iocs: list[str]
    overlap_counts: dict[str, int]
    explanation: list[str]


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
    if not left and not right:
        return 0.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def compare_fingerprints(
    left: CaseFingerprint,
    right: CaseFingerprint,
) -> tuple[float, dict[str, float]]:
    parts = {
        "techniques": _jaccard(left.techniques, right.techniques),
        "event_ids": _jaccard(left.event_ids, right.event_ids),
        "processes": _jaccard(left.processes, right.processes),
        "iocs": _jaccard(left.iocs, right.iocs),
    }
    score = sum(parts[key] * WEIGHTS[key] for key in parts) * 100
    return round(score, 1), {
        key: round(value * 100, 1)
        for key, value in parts.items()
    }


def _strength(score: float, shared_dimensions: int) -> str:
    if score >= 70 and shared_dimensions >= 2:
        return "strong"
    if score >= 40 and shared_dimensions >= 2:
        return "moderate"
    return "weak"


def _find_similar_from_records(
    events: list[Event],
    cases,
    *,
    limit: int = 5,
    min_score: float = 15.0,
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
        score, component_scores = compare_fingerprints(current, historical)
        if score < max(0.0, min(100.0, float(min_score))):
            continue

        shared_techniques = sorted(current.techniques & historical.techniques)
        shared_event_ids = sorted(current.event_ids & historical.event_ids)
        shared_processes = sorted(current.processes & historical.processes)
        shared_iocs = sorted(current.iocs & historical.iocs)
        overlap_counts = {
            "techniques": len(shared_techniques),
            "event_ids": len(shared_event_ids),
            "processes": len(shared_processes),
            "iocs": len(shared_iocs),
        }
        shared_dimensions = sum(1 for count in overlap_counts.values() if count > 0)
        strength = _strength(score, shared_dimensions)

        explanation: list[str] = [
            (
                "Similarity breakdown: "
                + ", ".join(
                    f"{key}={component_scores[key]}%"
                    for key in ("techniques", "event_ids", "processes", "iocs")
                )
            ),
            f"Match strength: {strength} across {shared_dimensions}/4 evidence dimensions.",
        ]
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

        matches.append(
            SimilarCase(
                case_id=case.case_id,
                title=case.title or case.case_id,
                score=score,
                strength=strength,
                shared_dimensions=shared_dimensions,
                component_scores=component_scores,
                shared_techniques=shared_techniques,
                shared_event_ids=shared_event_ids,
                shared_processes=shared_processes,
                shared_iocs=shared_iocs,
                overlap_counts=overlap_counts,
                explanation=explanation,
            )
        )

    return sorted(
        matches,
        key=lambda item: (
            -item.score,
            -item.shared_dimensions,
            item.case_id,
        ),
    )[:max(1, min(int(limit), 50))]


def find_similar_cases(
    events: list[Event],
    database: str | Path,
    *,
    limit: int = 5,
    min_score: float = 15.0,
    exclude_case_id: str | None = None,
) -> list[SimilarCase]:
    return _find_similar_from_records(
        events,
        list_cases(database),
        limit=limit,
        min_score=min_score,
        exclude_case_id=exclude_case_id,
    )


def find_similar_cases_pg(
    events: list[Event],
    dsn: str,
    *,
    limit: int = 5,
    min_score: float = 15.0,
    exclude_case_id: str | None = None,
) -> list[SimilarCase]:
    return _find_similar_from_records(
        events,
        list_cases_pg(dsn),
        limit=limit,
        min_score=min_score,
        exclude_case_id=exclude_case_id,
    )


def _payload(matches: list[SimilarCase], min_score: float) -> dict:
    return {
        "matches": [asdict(item) for item in matches],
        "summary": {
            "matches": len(matches),
            "highest_score": matches[0].score if matches else 0.0,
            "strong_matches": sum(1 for item in matches if item.strength == "strong"),
            "moderate_matches": sum(
                1 for item in matches if item.strength == "moderate"
            ),
            "min_score": min_score,
        },
        "weights": {
            key: int(value * 100)
            for key, value in WEIGHTS.items()
        },
        "interpretation": (
            "Similarity is evidence/behavior overlap, not attribution. "
            "Strength also considers how many independent evidence dimensions overlap."
        ),
    }


def similarity_payload(
    events: list[Event],
    database: str | Path,
    *,
    limit: int = 5,
    min_score: float = 15.0,
    exclude_case_id: str | None = None,
) -> dict:
    return _payload(
        find_similar_cases(
            events,
            database,
            limit=limit,
            min_score=min_score,
            exclude_case_id=exclude_case_id,
        ),
        min_score,
    )


def similarity_payload_pg(
    events: list[Event],
    dsn: str,
    *,
    limit: int = 5,
    min_score: float = 15.0,
    exclude_case_id: str | None = None,
) -> dict:
    return _payload(
        find_similar_cases_pg(
            events,
            dsn,
            limit=limit,
            min_score=min_score,
            exclude_case_id=exclude_case_id,
        ),
        min_score,
    )


def render_similarity(
    events: list[Event],
    database: str | Path,
    *,
    limit: int = 5,
    min_score: float = 15.0,
    exclude_case_id: str | None = None,
) -> str:
    payload = similarity_payload(
        events,
        database,
        limit=limit,
        min_score=min_score,
        exclude_case_id=exclude_case_id,
    )
    lines = [
        "SOCMind Historical Case Similarity",
        "==================================",
        payload["interpretation"],
        f"minimum_score={min_score}%",
        "",
    ]
    if not payload["matches"]:
        lines.append("No comparable evidence-linked historical cases met the threshold.")
        return "\n".join(lines)

    for item in payload["matches"]:
        lines.append(
            f"{item['case_id']} | {item['score']}% | {item['strength']} | "
            f"{item['shared_dimensions']}/4 dimensions | {item['title']}"
        )
        for reason in item["explanation"]:
            lines.append(f"  - {reason}")
    return "\n".join(lines)
