from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from math import sqrt
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
    classified_sample_size: int
    unclassified_sample_size: int
    true_positive_rate: float | None
    false_positive_rate: float | None
    false_positive_rate_low: float | None
    false_positive_rate_high: float | None
    sample_sufficiency: str
    status: str
    noisy: bool
    score: int


def _is_fp(value: str) -> bool:
    return value.lower() in {
        "false-positive", "false_positive", "benign-positive", "benign_positive"
    }


def _is_tp(value: str) -> bool:
    return value.lower() in {
        "true-positive", "true_positive", "malicious", "confirmed"
    }


def _wilson_interval(successes: int, total: int) -> tuple[float, float] | None:
    if total <= 0:
        return None
    z = 1.96
    p = successes / total
    denominator = 1 + (z * z / total)
    center = (p + (z * z / (2 * total))) / denominator
    margin = (
        z
        * sqrt((p * (1 - p) / total) + (z * z / (4 * total * total)))
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _sample_sufficiency(classified: int) -> str:
    if classified < 5:
        return "insufficient"
    if classified < 20:
        return "limited"
    return "established"


def detection_health(records: list[DispositionRecord]) -> list[RuleHealth]:
    grouped: dict[str, list[DispositionRecord]] = {}
    for record in records:
        grouped.setdefault(record.rule_id, []).append(record)

    rows: list[RuleHealth] = []
    for rule_id, group in sorted(grouped.items()):
        tp = sum(1 for item in group if _is_tp(item.disposition))
        fp = sum(1 for item in group if _is_fp(item.disposition))
        classified = tp + fp
        unclassified = len(group) - classified

        if classified:
            tp_rate = tp / classified
            fp_rate = fp / classified
            interval = _wilson_interval(fp, classified)
            fp_low, fp_high = interval if interval else (None, None)
        else:
            tp_rate = None
            fp_rate = None
            fp_low = fp_high = None

        sufficiency = _sample_sufficiency(classified)

        noisy = (
            classified >= 5
            and fp_rate is not None
            and fp_rate >= 0.5
            and fp_low is not None
            and fp_low >= 0.20
        )

        if sufficiency == "insufficient":
            status = "insufficient-data"
        elif noisy:
            status = "noisy"
        elif fp_rate is not None and fp_rate >= 0.30:
            status = "watch"
        else:
            status = "stable"

        score = 100
        if fp_rate is not None:
            score -= round(fp_rate * 60)
        if sufficiency == "insufficient":
            score -= 20
        elif sufficiency == "limited":
            score -= 5
        if unclassified:
            unclassified_ratio = unclassified / len(group)
            score -= round(unclassified_ratio * 10)
        score = max(0, min(100, score))

        rows.append(
            RuleHealth(
                rule_id=rule_id,
                sample_size=len(group),
                classified_sample_size=classified,
                unclassified_sample_size=unclassified,
                true_positive_rate=tp_rate,
                false_positive_rate=fp_rate,
                false_positive_rate_low=fp_low,
                false_positive_rate_high=fp_high,
                sample_sufficiency=sufficiency,
                status=status,
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
        if observed
        else None
    )

    return {
        "summary": {
            "events": len(events),
            "findings": len(findings),
            "rules": len(rules),
            "observed_techniques": len(observed),
            "coverage_percent": coverage_pct,
            "noisy_rules": sum(1 for row in health if row.noisy),
            "watch_rules": sum(1 for row in health if row.status == "watch"),
            "insufficient_data_rules": sum(
                1 for row in health if row.status == "insufficient-data"
            ),
            "dispositions": len(records),
            "classified_dispositions": sum(
                row.classified_sample_size for row in health
            ),
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
