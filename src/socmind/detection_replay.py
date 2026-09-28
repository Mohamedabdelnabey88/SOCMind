from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

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
    technique_aligned_detected: bool


@dataclass(frozen=True, slots=True)
class TechniqueVisibility:
    technique: str
    observed_steps: int
    detected_steps: int
    first_observed_step: int
    first_detected_step: int | None
    first_observed_at: str
    first_detected_at: str | None
    blind_seconds_until_detection: float | None
    matching_rule_ids: list[str]
    tagged_rule_ids: list[str]
    state: str


@dataclass(frozen=True, slots=True)
class DetectionReplayResult:
    total_steps: int
    meaningful_steps: int
    detected_steps: int
    first_detection_step: int | None
    first_meaningful_detection_step: int | None
    blind_steps_before_first_detection: int
    visibility_percent: float
    time_to_first_detection_seconds: float | None
    observed_techniques: list[str]
    covered_techniques: list[str]
    detected_techniques: list[str]
    gap_techniques: list[str]
    technique_visibility: list[TechniqueVisibility]
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


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def replay_detection(events: list[Event], rules: list[DetectionRule]) -> DetectionReplayResult:
    ordered = sorted(events, key=lambda item: item.timestamp)
    findings = analyze(ordered)

    event_techniques: dict[tuple, set[str]] = {}
    for finding in findings:
        techniques = {_technique_id(value) for value in finding.techniques}
        for evidence in finding.evidence:
            event_techniques.setdefault(_event_key(evidence), set()).update(techniques)

    matched_by_event: dict[tuple, list[str]] = {}
    rule_by_id = {rule.id: rule for rule in rules}
    for rule in rules:
        for event in evaluate_rule(rule, ordered):
            matched_by_event.setdefault(_event_key(event), []).append(rule.id)

    steps: list[DetectionStep] = []
    for index, event in enumerate(ordered, 1):
        techniques = sorted(event_techniques.get(_event_key(event), set()))
        matched_rules = sorted(set(matched_by_event.get(_event_key(event), [])))
        aligned = any(
            set(rule_by_id[rule_id].attack_techniques) & set(techniques)
            for rule_id in matched_rules
            if rule_id in rule_by_id
        )
        steps.append(
            DetectionStep(
                index=index,
                timestamp=event.timestamp.isoformat(),
                event_id=event.event_id,
                host=event.host,
                techniques=techniques,
                matched_rules=matched_rules,
                detected=bool(matched_rules),
                technique_aligned_detected=aligned,
            )
        )

    meaningful = [step for step in steps if step.techniques]
    detected_meaningful = [
        step for step in meaningful if step.technique_aligned_detected
    ]
    first_detection = next((step.index for step in steps if step.detected), None)
    first_meaningful_detection = next(
        (step.index for step in meaningful if step.technique_aligned_detected),
        None,
    )

    if first_meaningful_detection is not None:
        blind_before = sum(
            1
            for step in meaningful
            if step.index < first_meaningful_detection
            and not step.technique_aligned_detected
        )
    else:
        blind_before = len(meaningful)

    observed = sorted({
        technique
        for step in meaningful
        for technique in step.techniques
    })
    tagged_by_technique: dict[str, set[str]] = {}
    for rule in rules:
        for technique in rule.attack_techniques:
            tagged_by_technique.setdefault(technique, set()).add(rule.id)

    detected_by_technique: dict[str, set[str]] = {}
    for step in meaningful:
        if not step.matched_rules:
            continue
        for technique in step.techniques:
            for rule_id in step.matched_rules:
                rule = rule_by_id.get(rule_id)
                if rule and technique in rule.attack_techniques:
                    detected_by_technique.setdefault(technique, set()).add(rule_id)

    covered = sorted(set(observed) & set(tagged_by_technique))
    detected_techniques = sorted(set(observed) & set(detected_by_technique))
    gaps = sorted(set(observed) - set(tagged_by_technique))
    visibility = (
        round((len(detected_meaningful) / len(meaningful)) * 100, 1)
        if meaningful else 0.0
    )

    time_to_first_detection = None
    if meaningful and first_meaningful_detection is not None:
        first_observed_time = _parse_time(meaningful[0].timestamp)
        detection_step = next(
            step for step in meaningful if step.index == first_meaningful_detection
        )
        time_to_first_detection = max(
            0.0,
            round(
                (_parse_time(detection_step.timestamp) - first_observed_time).total_seconds(),
                3,
            ),
        )

    visibility_rows: list[TechniqueVisibility] = []
    for technique in observed:
        observed_steps = [step for step in meaningful if technique in step.techniques]
        detected_steps_for_technique = [
            step
            for step in observed_steps
            if any(
                rule_id in detected_by_technique.get(technique, set())
                for rule_id in step.matched_rules
            )
        ]
        first_observed = observed_steps[0]
        first_detected = (
            detected_steps_for_technique[0]
            if detected_steps_for_technique
            else None
        )
        blind_seconds = None
        if first_detected is not None:
            blind_seconds = max(
                0.0,
                round(
                    (
                        _parse_time(first_detected.timestamp)
                        - _parse_time(first_observed.timestamp)
                    ).total_seconds(),
                    3,
                ),
            )

        tagged_ids = sorted(tagged_by_technique.get(technique, set()))
        matching_ids = sorted(detected_by_technique.get(technique, set()))
        if matching_ids:
            state = "detected"
        elif tagged_ids:
            state = "covered-not-triggered"
        else:
            state = "gap"

        visibility_rows.append(
            TechniqueVisibility(
                technique=technique,
                observed_steps=len(observed_steps),
                detected_steps=len(detected_steps_for_technique),
                first_observed_step=first_observed.index,
                first_detected_step=first_detected.index if first_detected else None,
                first_observed_at=first_observed.timestamp,
                first_detected_at=first_detected.timestamp if first_detected else None,
                blind_seconds_until_detection=blind_seconds,
                matching_rule_ids=matching_ids,
                tagged_rule_ids=tagged_ids,
                state=state,
            )
        )

    return DetectionReplayResult(
        total_steps=len(steps),
        meaningful_steps=len(meaningful),
        detected_steps=len(detected_meaningful),
        first_detection_step=first_detection,
        first_meaningful_detection_step=first_meaningful_detection,
        blind_steps_before_first_detection=blind_before,
        visibility_percent=visibility,
        time_to_first_detection_seconds=time_to_first_detection,
        observed_techniques=observed,
        covered_techniques=covered,
        detected_techniques=detected_techniques,
        gap_techniques=gaps,
        technique_visibility=visibility_rows,
        steps=steps,
    )


def detection_replay_payload(events: list[Event], rules: list[DetectionRule]) -> dict:
    return asdict(replay_detection(events, rules))


def render_detection_replay(events: list[Event], rules: list[DetectionRule]) -> str:
    result = replay_detection(events, rules)
    lines = [
        "SOCMind Detection Replay",
        "========================",
        f"steps={result.total_steps}",
        f"meaningful_steps={result.meaningful_steps}",
        f"detected_steps={result.detected_steps}",
        f"first_detection_step={result.first_detection_step or '-'}",
        f"first_meaningful_detection_step={result.first_meaningful_detection_step or '-'}",
        f"blind_steps_before_first_detection={result.blind_steps_before_first_detection}",
        f"time_to_first_detection_seconds={result.time_to_first_detection_seconds if result.time_to_first_detection_seconds is not None else '-'}",
        f"visibility={result.visibility_percent}%",
        "",
        "Technique visibility:",
    ]
    for row in result.technique_visibility:
        lines.append(
            f"- {row.technique}: {row.state} | first_observed={row.first_observed_step} "
            f"| first_detected={row.first_detected_step or '-'} "
            f"| blind_seconds={row.blind_seconds_until_detection if row.blind_seconds_until_detection is not None else '-'} "
            f"| matching_rules={','.join(row.matching_rule_ids) or '-'}"
        )

    lines += ["", "Attack chain:"]
    for step in result.steps:
        if not step.techniques:
            continue
        state = (
            "DETECTED"
            if step.technique_aligned_detected
            else ("RULE-MATCH-NONALIGNED" if step.detected else "BLIND")
        )
        rules_text = ",".join(step.matched_rules) if step.matched_rules else "-"
        lines.append(
            f"- step {step.index}: {step.event_id} | {state} | "
            f"techniques={','.join(step.techniques)} | rules={rules_text}"
        )
    return "\n".join(lines)
