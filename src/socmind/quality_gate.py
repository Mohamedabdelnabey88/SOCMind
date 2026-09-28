from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .contradiction import review_hypotheses
from .engine import analyze
from .hypothesis import generate_hypotheses
from .ioc import extract_iocs
from .models import Event


@dataclass(frozen=True, slots=True)
class QualityItem:
    key: str
    label: str
    complete: bool
    evidence: str
    applicable: bool = True
    analyst_confirmation_required: bool = False


@dataclass(frozen=True, slots=True)
class QualityReview:
    completed: int
    total: int
    percentage: float
    items: list[QualityItem]
    outstanding: list[str]
    not_applicable: list[str]


def _checklist_flag(checklist: dict, key: str) -> bool:
    return checklist.get(key) is True


def review_investigation(
    events: list[Event],
    *,
    checklist: dict | None = None,
) -> QualityReview:
    checklist = checklist or {}
    findings = analyze(events)
    hypotheses = generate_hypotheses(findings)
    hypothesis_reviews = review_hypotheses(events)

    has_process_events = any(event.process for event in events)
    has_process_ancestry = any(
        event.process and event.parent_process for event in events
    )
    iocs = extract_iocs(events)
    techniques = {
        technique
        for finding in findings
        for technique in finding.techniques
    }
    has_persistence = any(
        "persistence" in finding.title.lower() for finding in findings
    )
    hosts = {event.host for event in events if event.host}
    has_explicit_contradiction = any(
        review.contradicting for review in hypothesis_reviews
    )
    has_validation_gaps = any(
        review.validation_gaps or review.unresolved
        for review in hypothesis_reviews
    )

    items = [
        QualityItem(
            "evidence",
            "Evidence available",
            bool(events),
            f"{len(events)} event(s)",
        ),
        QualityItem(
            "timeline",
            "Timeline reconstructed",
            len(events) >= 2,
            f"{len(events)} ordered event(s)",
        ),
        QualityItem(
            "process_ancestry",
            "Process ancestry reviewed",
            has_process_ancestry or _checklist_flag(checklist, "process_ancestry_reviewed"),
            (
                "parent/child process evidence present"
                if has_process_ancestry
                else "process telemetry exists; ancestry review not confirmed"
            ),
            applicable=has_process_events,
            analyst_confirmation_required=has_process_events and not has_process_ancestry,
        ),
        QualityItem(
            "iocs",
            "IOCs reviewed",
            _checklist_flag(checklist, "iocs_reviewed"),
            (
                f"{len(iocs)} IOC(s) extracted; analyst review recorded"
                if iocs and _checklist_flag(checklist, "iocs_reviewed")
                else f"{len(iocs)} IOC(s) extracted; analyst review not recorded"
                if iocs
                else "no IOCs extracted from current evidence"
            ),
            applicable=bool(iocs),
            analyst_confirmation_required=bool(iocs),
        ),
        QualityItem(
            "attack",
            "MITRE ATT&CK mapping",
            bool(techniques),
            f"{len(techniques)} mapped technique(s)",
            applicable=bool(findings),
        ),
        QualityItem(
            "hypotheses",
            "Hypotheses documented",
            bool(hypotheses),
            f"{len(hypotheses)} hypothesis/hypotheses",
            applicable=bool(findings),
        ),
        QualityItem(
            "contradiction_review",
            "Alternative / contradicting context reviewed",
            (
                has_explicit_contradiction
                or _checklist_flag(checklist, "contradiction_reviewed")
            ),
            (
                "explicit alternative/contradicting context recorded"
                if has_explicit_contradiction
                else "analyst contradiction review recorded"
                if _checklist_flag(checklist, "contradiction_reviewed")
                else "no explicit contradiction found; analyst review not recorded"
            ),
            applicable=bool(hypotheses),
            analyst_confirmation_required=bool(hypotheses) and not has_explicit_contradiction,
        ),
        QualityItem(
            "validation_gaps",
            "Validation gaps dispositioned",
            (
                not has_validation_gaps
                or _checklist_flag(checklist, "validation_gaps_reviewed")
            ),
            (
                "no unresolved validation gaps"
                if not has_validation_gaps
                else "analyst review recorded"
                if _checklist_flag(checklist, "validation_gaps_reviewed")
                else "unresolved validation questions remain"
            ),
            applicable=bool(hypotheses),
            analyst_confirmation_required=has_validation_gaps,
        ),
        QualityItem(
            "persistence",
            "Persistence validation",
            (
                not has_persistence
                or _checklist_flag(checklist, "persistence_validated")
            ),
            (
                "persistence not observed"
                if not has_persistence
                else "analyst validation recorded"
                if _checklist_flag(checklist, "persistence_validated")
                else "persistence observed; analyst validation not recorded"
            ),
            applicable=has_persistence,
            analyst_confirmation_required=has_persistence,
        ),
        QualityItem(
            "scope",
            "Scope validation",
            len(hosts) > 1 or _checklist_flag(checklist, "scope_validated"),
            (
                f"{len(hosts)} hosts represented in evidence"
                if len(hosts) > 1
                else "single-host evidence; analyst scope validation recorded"
                if _checklist_flag(checklist, "scope_validated")
                else "single-host evidence; broader scope not validated"
            ),
            analyst_confirmation_required=len(hosts) <= 1,
        ),
        QualityItem(
            "detection_feedback",
            "Detection feedback completed",
            _checklist_flag(checklist, "detection_feedback"),
            (
                "analyst feedback recorded"
                if _checklist_flag(checklist, "detection_feedback")
                else "not recorded"
            ),
            analyst_confirmation_required=True,
        ),
        QualityItem(
            "handoff",
            "Handoff readiness",
            _checklist_flag(checklist, "handoff_complete"),
            (
                "handoff marked complete"
                if _checklist_flag(checklist, "handoff_complete")
                else "not recorded"
            ),
            analyst_confirmation_required=True,
        ),
    ]

    applicable = [item for item in items if item.applicable]
    completed = sum(1 for item in applicable if item.complete)
    outstanding = [item.label for item in applicable if not item.complete]
    not_applicable = [item.label for item in items if not item.applicable]

    return QualityReview(
        completed=completed,
        total=len(applicable),
        percentage=(
            round((completed / len(applicable)) * 100, 1)
            if applicable
            else 100.0
        ),
        items=items,
        outstanding=outstanding,
        not_applicable=not_applicable,
    )


def load_checklist(path: str | Path | None) -> dict:
    if path is None:
        return {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Quality checklist must be a JSON object")
    return raw


def quality_payload(events: list[Event], *, checklist: dict | None = None) -> dict:
    review = review_investigation(events, checklist=checklist)
    return {
        "completed": review.completed,
        "total": review.total,
        "percentage": review.percentage,
        "items": [asdict(item) for item in review.items],
        "outstanding": review.outstanding,
        "not_applicable": review.not_applicable,
    }


def render_quality_review(events: list[Event], *, checklist: dict | None = None) -> str:
    review = review_investigation(events, checklist=checklist)
    lines = [
        "SOCMind Investigation Quality Gate",
        "==================================",
        f"completeness={review.completed}/{review.total} ({review.percentage}%)",
        "",
    ]
    for item in review.items:
        state = "N/A" if not item.applicable else ("OK" if item.complete else "TODO")
        analyst = " | analyst-confirmation" if item.analyst_confirmation_required else ""
        lines.append(f"[{state}] {item.label} | {item.evidence}{analyst}")
    if review.outstanding:
        lines += ["", "Outstanding:"]
        lines += [f"- {item}" for item in review.outstanding]
    if review.not_applicable:
        lines += ["", "Not applicable:"]
        lines += [f"- {item}" for item in review.not_applicable]
    return "\n".join(lines)
