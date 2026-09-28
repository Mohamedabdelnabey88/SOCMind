from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .coverage import build_coverage
from .detections import DetectionRule, load_rules
from .engine import analyze
from .io import load_jsonl
from .tuning import DispositionRecord, load_dispositions


@dataclass(frozen=True, slots=True)
class RuleHealth:
    rule_id: str
    sample_size: int
    true_positive_rate: float | None
    false_positive_rate: float | None
    noisy: bool
    score: int


def _is_fp(value: str) -> bool:
    return value.lower() in {
        "false-positive", "false_positive", "benign-positive", "benign_positive"
    }


def _is_tp(value: str) -> bool:
    return value.lower() in {"true-positive", "true_positive", "malicious", "confirmed"}


def detection_health(records: list[DispositionRecord]) -> list[RuleHealth]:
    grouped: dict[str, list[DispositionRecord]] = {}
    for record in records:
        grouped.setdefault(record.rule_id, []).append(record)

    rows: list[RuleHealth] = []
    for rule_id, group in sorted(grouped.items()):
        tp = sum(1 for item in group if _is_tp(item.disposition))
        fp = sum(1 for item in group if _is_fp(item.disposition))
        classified = tp + fp
        if classified:
            tp_rate = tp / classified
            fp_rate = fp / classified
        else:
            tp_rate = None
            fp_rate = None

        noisy = len(group) >= 5 and fp_rate is not None and fp_rate >= 0.5
        score = 100
        if fp_rate is not None:
            score -= round(fp_rate * 60)
        if len(group) < 5:
            score -= 10
        score = max(0, min(100, score))

        rows.append(
            RuleHealth(
                rule_id=rule_id,
                sample_size=len(group),
                true_positive_rate=tp_rate,
                false_positive_rate=fp_rate,
                noisy=noisy,
                score=score,
            )
        )
    return rows


def lead_snapshot(
    events_path: str | Path,
    *,
    rules_dir: str | Path,
    dispositions_path: str | Path | None = None,
) -> dict:
    events = load_jsonl(events_path)
    findings = analyze(events)
    rules: list[DetectionRule] = load_rules(rules_dir)
    coverage = build_coverage(findings, rules)

    users = Counter(event.user for event in events if event.user)
    hosts = Counter(event.host for event in events if event.host)

    records = load_dispositions(dispositions_path) if dispositions_path else []
    health = detection_health(records)

    observed = [row for row in coverage if row.observed]
    observed_covered = [row for row in observed if row.covered]
    coverage_pct = (
        round((len(observed_covered) / len(observed)) * 100, 1)
        if observed else None
    )

    return {
        "summary": {
            "events": len(events),
            "findings": len(findings),
            "rules": len(rules),
            "observed_techniques": len(observed),
            "coverage_percent": coverage_pct,
            "noisy_rules": sum(1 for row in health if row.noisy),
            "dispositions": len(records),
        },
        "top_users": [
            {"user": value, "events": count}
            for value, count in users.most_common(5)
        ],
        "top_hosts": [
            {"host": value, "events": count}
            for value, count in hosts.most_common(5)
        ],
        "coverage": [
            {
                "technique": row.technique,
                "observed": row.observed,
                "covered": row.covered,
                "rule_count": row.rule_count,
                "rules": row.rules,
            }
            for row in coverage
        ],
        "detection_health": [asdict(row) for row in health],
    }
