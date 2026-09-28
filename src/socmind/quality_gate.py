from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

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


@dataclass(frozen=True, slots=True)
class QualityReview:
    completed: int
    total: int
    percentage: float
    items: list[QualityItem]
    outstanding: list[str]


def review_investigation(
    events: list[Event],
    *,
    checklist: dict | None = None,
) -> QualityReview:
    checklist = checklist or {}
    findings = analyze(events)
    hypotheses = generate_hypotheses(findings)
    has_process_ancestry = any(
        event.process and event.parent_process for event in events
    )
    has_iocs = bool(extract_iocs(events))
    techniques = {
        technique
        for finding in findings
        for technique in finding.techniques
    }
    has_persistence = any(
        "Persistence" in finding.title for finding in findings
    )
    has_scope = len({event.host for event in events if event.host}) > 1 or bool(
        checklist.get("scope_validated")
    )
    contradicting = any(h.contradicting for h in hypotheses)

    items = [
        QualityItem("evidence", "Evidence available", bool(events), f"{len(events)} event(s)"),
        QualityItem("timeline", "Timeline reconstructed", len(events) >= 2, f"{len(events)} ordered event(s)"),
        QualityItem(
            "process_ancestry",
            "Process ancestry available",
            has_process_ancestry,
            "parent/child process evidence present" if has_process_ancestry else "no parent/child process pair",
        ),
        QualityItem(
            "iocs",
            "IOCs identified/reviewed",
            has_iocs and bool(checklist.get("iocs_reviewed")),
            "IOCs present and analyst review recorded" if has_iocs and checklist.get("iocs_reviewed") else (
                "IOCs present but review not recorded" if has_iocs else "no IOCs extracted"
            ),
        ),
        QualityItem("attack", "MITRE ATT&CK mapping", bool(techniques), f"{len(techniques)} technique(s)"),
        QualityItem("hypotheses", "Hypotheses documented", bool(hypotheses), f"{len(hypotheses)} hypothesis/hypotheses"),
        QualityItem(
            "contradicting",
            "Contradicting evidence / validation gaps documented",
            contradicting,
            "validation gaps retained" if contradicting else "no contradicting/gap evidence recorded",
        ),
        QualityItem(
            "persistence",
            "Persistence validation",
            (not has_persistence) or bool(checklist.get("persistence_validated")),
            "not observed" if not has_persistence else (
                "analyst validation recorded" if checklist.get("persistence_validated") else "persistence observed; validation not recorded"
            ),
        ),
        QualityItem(
            "scope",
            "Scope validation",
            has_scope,
            "multi-host scope or analyst validation recorded" if has_scope else "single-host scope; validation not recorded",
        ),
        QualityItem(
            "detection_feedback",
            "Detection feedback completed",
            bool(checklist.get("detection_feedback")),
            "analyst feedback recorded" if checklist.get("detection_feedback") else "not recorded",
        ),
        QualityItem(
            "handoff",
            "Handoff readiness",
            bool(checklist.get("handoff_complete")),
            "handoff marked complete" if checklist.get("handoff_complete") else "not recorded",
        ),
    ]
    completed = sum(1 for item in items if item.complete)
    outstanding = [item.label for item in items if not item.complete]
    return QualityReview(
        completed=completed,
        total=len(items),
        percentage=round((completed / len(items)) * 100, 1),
        items=items,
        outstanding=outstanding,
    )


def load_checklist(path: str | Path | None) -> dict:
    if path is None:
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))


def quality_payload(events: list[Event], *, checklist: dict | None = None) -> dict:
    review = review_investigation(events, checklist=checklist)
    return {
        "completed": review.completed,
        "total": review.total,
        "percentage": review.percentage,
        "items": [asdict(item) for item in review.items],
        "outstanding": review.outstanding,
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
        lines.append(f"[{'OK' if item.complete else 'TODO'}] {item.label} | {item.evidence}")
    if review.outstanding:
        lines += ["", "Outstanding:"]
        lines += [f"- {item}" for item in review.outstanding]
    return "\n".join(lines)
