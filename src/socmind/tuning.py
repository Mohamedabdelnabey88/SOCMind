from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable


@dataclass(slots=True)
class DispositionRecord:
    rule_id: str
    disposition: str
    reason: str | None = None
    user: str | None = None
    host: str | None = None
    process: str | None = None


@dataclass(slots=True)
class TuningSuggestion:
    rule_id: str
    false_positive_rate: float
    sample_size: int
    common_reasons: list[str]
    recommendation: str


def suggest_tuning(records: Iterable[DispositionRecord], *, min_samples: int = 5) -> list[TuningSuggestion]:
    grouped: dict[str, list[DispositionRecord]] = {}
    for record in records:
        grouped.setdefault(record.rule_id, []).append(record)

    suggestions: list[TuningSuggestion] = []
    for rule_id, group in sorted(grouped.items()):
        if len(group) < min_samples:
            continue
        fp = [
            record for record in group
            if record.disposition.lower() in {"false-positive", "false_positive", "benign-positive", "benign_positive"}
        ]
        rate = len(fp) / len(group)
        if rate < 0.5:
            continue
        reasons = Counter(
            record.reason.strip()
            for record in fp
            if record.reason and record.reason.strip()
        )
        common = [reason for reason, _ in reasons.most_common(3)]
        suggestions.append(
            TuningSuggestion(
                rule_id=rule_id,
                false_positive_rate=rate,
                sample_size=len(group),
                common_reasons=common,
                recommendation=(
                    "Review rule scope and add evidence-based exclusions for repeated benign context; "
                    "do not suppress the underlying behavior globally."
                ),
            )
        )
    return suggestions
