from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from .engine import analyze
from .hypothesis import generate_hypotheses
from .models import Event


@dataclass(frozen=True, slots=True)
class ReplayHypothesis:
    name: str
    confidence: int
    delta: int


@dataclass(frozen=True, slots=True)
class ReplayStep:
    index: int
    timestamp: str
    event_id: str
    source: str
    host: str
    user: str | None
    process: str | None
    command_line: str | None
    new_findings: list[str]
    hypotheses: list[ReplayHypothesis]


def build_investigation_replay(events: list[Event]) -> list[ReplayStep]:
    ordered = sorted(events, key=lambda item: item.timestamp)
    previous_findings: set[str] = set()
    previous_confidence: dict[str, int] = {}
    steps: list[ReplayStep] = []

    for idx in range(1, len(ordered) + 1):
        prefix = ordered[:idx]
        findings = analyze(prefix)
        hypotheses = generate_hypotheses(findings)

        current_findings = {finding.title for finding in findings}
        newly_visible = sorted(current_findings - previous_findings)

        replay_hypotheses = [
            ReplayHypothesis(
                name=hypothesis.name,
                confidence=hypothesis.confidence,
                delta=hypothesis.confidence - previous_confidence.get(hypothesis.name, 0),
            )
            for hypothesis in hypotheses
        ]

        event = prefix[-1]
        steps.append(
            ReplayStep(
                index=idx,
                timestamp=event.timestamp.isoformat(),
                event_id=event.event_id,
                source=event.source,
                host=event.host,
                user=event.user,
                process=event.process,
                command_line=event.command_line,
                new_findings=newly_visible,
                hypotheses=replay_hypotheses,
            )
        )

        previous_findings = current_findings
        previous_confidence = {
            hypothesis.name: hypothesis.confidence for hypothesis in hypotheses
        }

    return steps


def replay_payload(events: list[Event]) -> dict:
    steps = build_investigation_replay(events)
    return {
        "steps": [
            {
                **{k: v for k, v in asdict(step).items() if k != "hypotheses"},
                "hypotheses": [asdict(item) for item in step.hypotheses],
            }
            for step in steps
        ],
        "summary": {
            "events": len(events),
            "steps": len(steps),
            "first_finding_step": next(
                (step.index for step in steps if step.new_findings),
                None,
            ),
            "final_hypotheses": len(steps[-1].hypotheses) if steps else 0,
        },
    }


def render_replay(events: list[Event]) -> str:
    steps = build_investigation_replay(events)
    lines = [
        "SOCMind Investigation Replay",
        "============================",
    ]
    for step in steps:
        lines.append(
            f"\n[{step.index}] {step.timestamp} | {step.source} | "
            f"{step.event_id} | {step.host}"
        )
        if step.process or step.command_line:
            lines.append(
                f"    process={step.process or '-'} | command={step.command_line or '-'}"
            )
        for finding in step.new_findings:
            lines.append(f"    + finding: {finding}")
        for hypothesis in step.hypotheses:
            delta = f"{hypothesis.delta:+d}" if hypothesis.delta else "0"
            lines.append(
                f"    ? {hypothesis.name}: {hypothesis.confidence}% (delta {delta})"
            )
    return "\n".join(lines)
