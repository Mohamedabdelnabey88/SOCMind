from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .contradiction import contradiction_payload
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
    severity: str
    status: str


@dataclass(frozen=True, slots=True)
class QualityReview:
    completed: int
    total: int
    percentage: float
    items: list[QualityItem]
    outstanding: list[str]
    blockers: list[str]
    warnings: list[str]
    readiness: str
    closure_allowed: bool


def _item(
    key: str,
    label: str,
    complete: bool,
    evidence: str,
    severity: str,
) -> QualityItem:
    if complete:
        status = "PASS"
    elif severity == "required":
        status = "BLOCK"
    else:
        status = "WARN"
    return QualityItem(key, label, complete, evidence, severity, status)


def review_investigation(
    events: list[Event],
    *,
    checklist: dict | None = None,
) -> QualityReview:
    checklist = checklist or {}
    findings = analyze(events)
    hypotheses = generate_hypotheses(findings)
    contradictions = contradiction_payload(events)

    has_process_ancestry = any(
        event.process and event.parent_process for event in events
    )
    iocs = extract_iocs(events)
    has_iocs = bool(iocs)
    techniques = {
        technique
        for finding in findings
        for technique in finding.techniques
    }
    has_persistence = any(
        "Persistence" in finding.title for finding in findings
    )
    scope_validated = bool(checklist.get("scope_validated"))
    contradiction_reviewed = bool(checklist.get("contradictions_reviewed"))

    items = [
        _item(
            "evidence",
            "Evidence available",
            bool(events),
            f"{len(events)} event(s)",
            "required",
        ),
        _item(
            "timeline",
            "Timeline reconstructed",
            len(events) >= 2,
            f"{len(events)} ordered event(s)",
            "required",
        ),
        _item(
            "process_ancestry",
            "Process ancestry reviewed",
            (not has_process_ancestry)
            or bool(checklist.get("process_ancestry_reviewed")),
            (
                "parent/child process evidence present and analyst review recorded"
                if has_process_ancestry and checklist.get("process_ancestry_reviewed")
                else (
                    "parent/child process evidence present but review not recorded"
                    if has_process_ancestry
                    else "no parent/child process pair; not applicable"
                )
            ),
            "conditional" if has_process_ancestry else "advisory",
        ),
        _item(
            "iocs",
            "IOCs identified/reviewed",
            (not has_iocs) or bool(checklist.get("iocs_reviewed")),
            (
                f"{len(iocs)} IOC(s) present and analyst review recorded"
                if has_iocs and checklist.get("iocs_reviewed")
                else (
                    f"{len(iocs)} IOC(s) present but review not recorded"
                    if has_iocs
                    else "no IOCs extracted; not applicable"
                )
            ),
            "conditional" if has_iocs else "advisory",
        ),
        _item(
            "attack",
            "MITRE ATT&CK mapping",
            bool(techniques),
            f"{len(techniques)} technique(s)",
            "required",
        ),
        _item(
            "hypotheses",
            "Hypotheses documented",
            bool(hypotheses),
            f"{len(hypotheses)} hypothesis/hypotheses",
            "required",
        ),
        _item(
            "contradictions",
            "Contradicting evidence / validation gaps reviewed",
            contradiction_reviewed,
            (
                f"{contradictions['summary']['contradicting_points']} contradiction/context point(s), "
                f"{contradictions['summary']['validation_gaps']} validation gap(s)"
            ),
            "required",
        ),
        _item(
            "persistence",
            "Persistence validation",
            (not has_persistence) or bool(checklist.get("persistence_validated")),
            (
                "not observed; not applicable"
                if not has_persistence
                else (
                    "analyst validation recorded"
                    if checklist.get("persistence_validated")
                    else "persistence observed; validation not recorded"
                )
            ),
            "conditional" if has_persistence else "advisory",
        ),
        _item(
            "scope",
            "Scope validation",
            scope_validated,
            (
                "analyst scope validation recorded"
                if scope_validated
                else (
                    f"scope validation not recorded; evidence spans {len({event.host for event in events if event.host})} host(s)"
                )
            ),
            "required",
        ),
        _item(
            "detection_feedback",
            "Detection feedback completed",
            bool(checklist.get("detection_feedback")),
            (
                "analyst feedback recorded"
                if checklist.get("detection_feedback")
                else "not recorded"
            ),
            "advisory",
        ),
        _item(
            "handoff",
            "Handoff readiness",
            bool(checklist.get("handoff_complete")),
            (
                "handoff marked complete"
                if checklist.get("handoff_complete")
                else "handoff not marked complete"
            ),
            "required",
        ),
    ]

    completed = sum(1 for item in items if item.complete)
    blockers = [
        item.label
        for item in items
        if not item.complete and item.severity == "required"
    ]
    warnings = [
        item.label
        for item in items
        if not item.complete and item.severity != "required"
    ]
    outstanding = [item.label for item in items if not item.complete]

    if blockers:
        readiness = "BLOCKED"
    elif warnings:
        readiness = "NEEDS_REVIEW"
    else:
        readiness = "READY"

    return QualityReview(
        completed=completed,
        total=len(items),
        percentage=round((completed / len(items)) * 100, 1),
        items=items,
        outstanding=outstanding,
        blockers=blockers,
        warnings=warnings,
        readiness=readiness,
        closure_allowed=not blockers,
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
        "readiness": review.readiness,
        "closure_allowed": review.closure_allowed,
        "items": [asdict(item) for item in review.items],
        "outstanding": review.outstanding,
        "blockers": review.blockers,
        "warnings": review.warnings,
    }


def render_quality_review(events: list[Event], *, checklist: dict | None = None) -> str:
    review = review_investigation(events, checklist=checklist)
    lines = [
        "SOCMind Investigation Quality Gate",
        "==================================",
        f"readiness={review.readiness}",
        f"closure_allowed={str(review.closure_allowed).lower()}",
        f"completeness={review.completed}/{review.total} ({review.percentage}%)",
        "",
    ]
    for item in review.items:
        lines.append(
            f"[{item.status}] {item.label} | severity={item.severity} | {item.evidence}"
        )
    if review.blockers:
        lines += ["", "Blocking closure:"]
        lines += [f"- {item}" for item in review.blockers]
    if review.warnings:
        lines += ["", "Warnings:"]
        lines += [f"- {item}" for item in review.warnings]
    return "\n".join(lines)
