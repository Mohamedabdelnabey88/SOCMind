from __future__ import annotations

from dataclasses import asdict, dataclass

from .detections import DetectionRule, evaluate_rule
from .engine import analyze
from .models import Event


@dataclass(frozen=True, slots=True)
class DetectionStep:
    index: int
    timestamp: str
    event_id: str
    host: str
    techniques: list[str]
    matched_rules: list[str]
    detected: bool


@dataclass(frozen=True, slots=True)
class DetectionReplayResult:
    total_steps: int
    meaningful_steps: int
    detected_steps: int
    first_detection_step: int | None
    blind_steps_before_first_detection: int
    visibility_percent: float
    observed_techniques: list[str]
    covered_techniques: list[str]
    gap_techniques: list[str]
    steps: list[DetectionStep]


def _technique_id(value: str) -> str:
    return value.split()[0].upper()


def _event_key(event: Event) -> tuple:
    return (
        event.timestamp,
        event.source,
        event.event_id,
        event.host,
        event.user,
        event.process,
        event.src_ip,
        event.dst_ip,
        event.command_line,
    )


def replay_detection(events: list[Event], rules: list[DetectionRule]) -> DetectionReplayResult:
    ordered = sorted(events, key=lambda item: item.timestamp)
    findings = analyze(ordered)

    event_techniques: dict[tuple, set[str]] = {}
    for finding in findings:
        techniques = {_technique_id(value) for value in finding.techniques}
        for evidence in finding.evidence:
            event_techniques.setdefault(_event_key(evidence), set()).update(techniques)

    matched_by_event: dict[tuple, list[str]] = {}
    for rule in rules:
        for event in evaluate_rule(rule, ordered):
            matched_by_event.setdefault(_event_key(event), []).append(rule.id)

    steps: list[DetectionStep] = []
    for index, event in enumerate(ordered, 1):
        techniques = sorted(event_techniques.get(_event_key(event), set()))
        matched_rules = sorted(set(matched_by_event.get(_event_key(event), [])))
        steps.append(
            DetectionStep(
                index=index,
                timestamp=event.timestamp.isoformat(),
                event_id=event.event_id,
                host=event.host,
                techniques=techniques,
                matched_rules=matched_rules,
                detected=bool(matched_rules),
            )
        )

    meaningful = [step for step in steps if step.techniques]
    detected_meaningful = [step for step in meaningful if step.detected]
    first_detection = next((step.index for step in steps if step.detected), None)
    blind_before = 0
    if first_detection is not None:
        blind_before = sum(
            1 for step in meaningful
            if step.index < first_detection and not step.detected
        )
    else:
        blind_before = len(meaningful)

    observed = sorted({
        technique for step in meaningful for technique in step.techniques
    })
    rule_techniques = {
        technique for rule in rules for technique in rule.attack_techniques
    }
    covered = sorted(set(observed) & rule_techniques)
    gaps = sorted(set(observed) - rule_techniques)
    visibility = (
        round((len(detected_meaningful) / len(meaningful)) * 100, 1)
        if meaningful else 0.0
    )

    return DetectionReplayResult(
        total_steps=len(steps),
        meaningful_steps=len(meaningful),
        detected_steps=len(detected_meaningful),
        first_detection_step=first_detection,
        blind_steps_before_first_detection=blind_before,
        visibility_percent=visibility,
        observed_techniques=observed,
        covered_techniques=covered,
        gap_techniques=gaps,
        steps=steps,
    )


def detection_replay_payload(events: list[Event], rules: list[DetectionRule]) -> dict:
    result = replay_detection(events, rules)
    payload = asdict(result)
    return payload


def render_detection_replay(events: list[Event], rules: list[DetectionRule]) -> str:
    result = replay_detection(events, rules)
    lines = [
        "SOCMind Detection Replay",
        "========================",
        f"steps={result.total_steps}",
        f"meaningful_steps={result.meaningful_steps}",
        f"detected_steps={result.detected_steps}",
        f"first_detection_step={result.first_detection_step or '-'}",
        f"blind_steps_before_first_detection={result.blind_steps_before_first_detection}",
        f"visibility={result.visibility_percent}%",
        "",
        "Attack chain:",
    ]
    for step in result.steps:
        if not step.techniques:
            continue
        state = "DETECTED" if step.detected else "BLIND"
        rules_text = ",".join(step.matched_rules) if step.matched_rules else "-"
        lines.append(
            f"- step {step.index}: {step.event_id} | {state} | "
            f"techniques={','.join(step.techniques)} | rules={rules_text}"
        )
    lines.append("")
    lines.append("Coverage:")
    for technique in result.observed_techniques:
        lines.append(
            f"- {technique}: {'COVERED' if technique in result.covered_techniques else 'GAP'}"
        )
    return "\n".join(lines)
