from __future__ import annotations

from dataclasses import asdict, dataclass

from .detection_replay import replay_detection
from .detections import DetectionRule
from .models import Event


@dataclass(frozen=True, slots=True)
class WhatIfResult:
    current: dict
    proposed: dict
    first_detection_step_improvement: int | None
    visibility_delta: float
    blind_step_delta: int
    newly_covered_techniques: list[str]


def compare_rule_packs(
    events: list[Event],
    current_rules: list[DetectionRule],
    proposed_rules: list[DetectionRule],
) -> WhatIfResult:
    current = replay_detection(events, current_rules)
    proposed = replay_detection(events, proposed_rules)

    improvement = None
    if current.first_detection_step is not None and proposed.first_detection_step is not None:
        improvement = current.first_detection_step - proposed.first_detection_step
    elif current.first_detection_step is None and proposed.first_detection_step is not None:
        improvement = current.total_steps - proposed.first_detection_step + 1

    return WhatIfResult(
        current={
            "first_detection_step": current.first_detection_step,
            "visibility_percent": current.visibility_percent,
            "blind_steps_before_first_detection": current.blind_steps_before_first_detection,
            "covered_techniques": current.covered_techniques,
        },
        proposed={
            "first_detection_step": proposed.first_detection_step,
            "visibility_percent": proposed.visibility_percent,
            "blind_steps_before_first_detection": proposed.blind_steps_before_first_detection,
            "covered_techniques": proposed.covered_techniques,
        },
        first_detection_step_improvement=improvement,
        visibility_delta=round(
            proposed.visibility_percent - current.visibility_percent,
            1,
        ),
        blind_step_delta=(
            current.blind_steps_before_first_detection
            - proposed.blind_steps_before_first_detection
        ),
        newly_covered_techniques=sorted(
            set(proposed.covered_techniques) - set(current.covered_techniques)
        ),
    )


def render_what_if(
    events: list[Event],
    current_rules: list[DetectionRule],
    proposed_rules: list[DetectionRule],
) -> str:
    result = compare_rule_packs(events, current_rules, proposed_rules)
    lines = [
        "SOCMind Detection What-If",
        "=========================",
        "",
        "CURRENT",
        f"first_detection={result.current['first_detection_step'] or '-'}",
        f"visibility={result.current['visibility_percent']}%",
        f"blind_before_detection={result.current['blind_steps_before_first_detection']}",
        "",
        "PROPOSED",
        f"first_detection={result.proposed['first_detection_step'] or '-'}",
        f"visibility={result.proposed['visibility_percent']}%",
        f"blind_before_detection={result.proposed['blind_steps_before_first_detection']}",
        "",
        "DELTA",
        f"first_detection_step_improvement={result.first_detection_step_improvement if result.first_detection_step_improvement is not None else '-'}",
        f"visibility_delta={result.visibility_delta:+.1f}%",
        f"blind_step_reduction={result.blind_step_delta:+d}",
        f"newly_covered={','.join(result.newly_covered_techniques) or '-'}",
    ]
    return "\n".join(lines)
