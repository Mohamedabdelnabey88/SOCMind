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
    blind: bool


@dataclass(frozen=True, slots=True)
class TechniqueVisibility:
    technique: str
    first_observed_step: int
    first_detected_step: int | None
    detection_delay_steps: int | None
    observed_steps: int
    detected_steps: int
    visibility_percent: float
    contributing_rules: list[str]


@dataclass(frozen=True, slots=True)
class RuleContribution:
    rule_id: str
    matched_steps: int
    first_match_step: int
    techniques: list[str]


@dataclass(frozen=True, slots=True)
class DetectionReplayResult:
    total_steps: int
    meaningful_steps: int
    detected_steps: int
    blind_steps: int
    first_detection_step: int | None
    blind_steps_before_first_detection: int
    visibility_percent: float
    observed_techniques: list[str]
    covered_techniques: list[str]
    gap_techniques: list[str]
    technique_visibility: list[TechniqueVisibility]
    rule_contributions: list[RuleContribution]
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
    rule_map = {rule.id: rule for rule in rules}
    for rule in rules:
        for event in evaluate_rule(rule, ordered):
            matched_by_event.setdefault(_event_key(event), []).append(rule.id)

    steps: list[DetectionStep] = []
    for index, event in enumerate(ordered, 1):
        techniques = sorted(event_techniques.get(_event_key(event), set()))
        matched_rules = sorted(set(matched_by_event.get(_event_key(event), [])))
        meaningful = bool(techniques)
        detected = bool(matched_rules)
        steps.append(
            DetectionStep(
                index=index,
                timestamp=event.timestamp.isoformat(),
                event_id=event.event_id,
                host=event.host,
                techniques=techniques,
                matched_rules=matched_rules,
                detected=detected,
                blind=meaningful and not detected,
            )
        )

    meaningful_steps = [step for step in steps if step.techniques]
    detected_meaningful = [step for step in meaningful_steps if step.detected]
    blind_meaningful = [step for step in meaningful_steps if step.blind]
    first_detection = next((step.index for step in meaningful_steps if step.detected), None)

    if first_detection is not None:
        blind_before = sum(
            1
            for step in meaningful_steps
            if step.index < first_detection and step.blind
        )
    else:
        blind_before = len(meaningful_steps)

    observed = sorted({
        technique
        for step in meaningful_steps
        for technique in step.techniques
    })
    rule_techniques = {
        technique
        for rule in rules
        for technique in rule.attack_techniques
    }
    covered = sorted(set(observed) & rule_techniques)
    gaps = sorted(set(observed) - rule_techniques)

    visibility = (
        round((len(detected_meaningful) / len(meaningful_steps)) * 100, 1)
        if meaningful_steps
        else 0.0
    )

    technique_visibility: list[TechniqueVisibility] = []
    for technique in observed:
        relevant = [step for step in meaningful_steps if technique in step.techniques]
        detected_relevant = [step for step in relevant if step.detected]
        first_observed = relevant[0].index
        first_detected = detected_relevant[0].index if detected_relevant else None
        contributing = sorted({
            rule_id
            for step in detected_relevant
            for rule_id in step.matched_rules
            if rule_id in rule_map and technique in rule_map[rule_id].attack_techniques
        })
        technique_visibility.append(
            TechniqueVisibility(
                technique=technique,
                first_observed_step=first_observed,
                first_detected_step=first_detected,
                detection_delay_steps=(
                    first_detected - first_observed
                    if first_detected is not None
                    else None
                ),
                observed_steps=len(relevant),
                detected_steps=len(detected_relevant),
                visibility_percent=round(
                    (len(detected_relevant) / len(relevant)) * 100,
                    1,
                ),
                contributing_rules=contributing,
            )
        )

    contributions: list[RuleContribution] = []
    for rule in rules:
        matched = [step for step in steps if rule.id in step.matched_rules]
        if not matched:
            continue
        contributions.append(
            RuleContribution(
                rule_id=rule.id,
                matched_steps=len(matched),
                first_match_step=matched[0].index,
                techniques=sorted(rule.attack_techniques),
            )
        )
    contributions.sort(key=lambda item: (item.first_match_step, item.rule_id))

    return DetectionReplayResult(
        total_steps=len(steps),
        meaningful_steps=len(meaningful_steps),
        detected_steps=len(detected_meaningful),
        blind_steps=len(blind_meaningful),
        first_detection_step=first_detection,
        blind_steps_before_first_detection=blind_before,
        visibility_percent=visibility,
        observed_techniques=observed,
        covered_techniques=covered,
        gap_techniques=gaps,
        technique_visibility=technique_visibility,
        rule_contributions=contributions,
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
        f"blind_steps={result.blind_steps}",
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

    lines += ["", "Per-technique visibility:"]
    for item in result.technique_visibility:
        detected = item.first_detected_step if item.first_detected_step is not None else "-"
        delay = item.detection_delay_steps if item.detection_delay_steps is not None else "-"
        lines.append(
            f"- {item.technique}: first_observed={item.first_observed_step} "
            f"first_detected={detected} delay={delay} "
            f"visibility={item.visibility_percent}%"
        )

    lines += ["", "Rule contribution:"]
    if result.rule_contributions:
        for item in result.rule_contributions:
            lines.append(
                f"- {item.rule_id}: first_match={item.first_match_step} "
                f"matched_steps={item.matched_steps} "
                f"techniques={','.join(item.techniques) or '-'}"
            )
    else:
        lines.append("- no rules matched")

    return "\n".join(lines)
