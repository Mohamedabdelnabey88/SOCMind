from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .command_center import list_cases
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
    shared_techniques: list[str]
    shared_event_ids: list[str]
    shared_processes: list[str]
    shared_iocs: list[str]
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


def compare_fingerprints(left: CaseFingerprint, right: CaseFingerprint) -> tuple[float, dict]:
    parts = {
        "techniques": _jaccard(left.techniques, right.techniques),
        "event_ids": _jaccard(left.event_ids, right.event_ids),
        "processes": _jaccard(left.processes, right.processes),
        "iocs": _jaccard(left.iocs, right.iocs),
    }
    weights = {
        "techniques": 0.40,
        "event_ids": 0.20,
        "processes": 0.20,
        "iocs": 0.20,
    }
    score = sum(parts[key] * weights[key] for key in parts) * 100
    return round(score, 1), parts


def find_similar_cases(
    events: list[Event],
    database: str | Path,
    *,
    limit: int = 5,
    exclude_case_id: str | None = None,
) -> list[SimilarCase]:
    current = fingerprint_case(events)
    matches: list[SimilarCase] = []

    for case in list_cases(database):
        if exclude_case_id and case.case_id == exclude_case_id:
            continue
        if not case.evidence_path:
            continue
        path = Path(case.evidence_path)
        if not path.is_file():
            continue
        try:
            historical_events = load_jsonl(path)
        except Exception:
            continue

        historical = fingerprint_case(historical_events)
        score, _ = compare_fingerprints(current, historical)
        if score <= 0:
            continue

        shared_techniques = sorted(current.techniques & historical.techniques)
        shared_event_ids = sorted(current.event_ids & historical.event_ids)
        shared_processes = sorted(current.processes & historical.processes)
        shared_iocs = sorted(current.iocs & historical.iocs)

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

        matches.append(
            SimilarCase(
                case_id=case.case_id,
                title=case.title or case.case_id,
                score=score,
                shared_techniques=shared_techniques,
                shared_event_ids=shared_event_ids,
                shared_processes=shared_processes,
                shared_iocs=shared_iocs,
                explanation=explanation,
            )
        )

    return sorted(matches, key=lambda item: (-item.score, item.case_id))[:max(1, limit)]


def similarity_payload(
    events: list[Event],
    database: str | Path,
    *,
    limit: int = 5,
    exclude_case_id: str | None = None,
) -> dict:
    matches = find_similar_cases(
        events,
        database,
        limit=limit,
        exclude_case_id=exclude_case_id,
    )
    return {
        "matches": [asdict(item) for item in matches],
        "summary": {
            "matches": len(matches),
            "highest_score": matches[0].score if matches else 0.0,
        },
        "interpretation": (
            "Similarity is evidence/behavior overlap, not attribution and not proof "
            "that cases share the same attacker."
        ),
    }


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
        lines.append(f"{item['case_id']} | {item['score']}% | {item['title']}")
        for reason in item["explanation"]:
            lines.append(f"  - {reason}")
    return "\n".join(lines)
