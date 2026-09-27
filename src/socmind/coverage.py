from __future__ import annotations

from dataclasses import dataclass

from .detections import DetectionRule
from .models import Finding


@dataclass(slots=True)
class CoverageRow:
    technique: str
    observed: bool
    rule_count: int
    rules: list[str]

    @property
    def covered(self) -> bool:
        return self.rule_count > 0


def _technique_id(value: str) -> str:
    return value.split()[0].upper()


def build_coverage(findings: list[Finding], rules: list[DetectionRule]) -> list[CoverageRow]:
    observed = {
        _technique_id(technique)
        for finding in findings
        for technique in finding.techniques
        if technique
    }
    rule_map: dict[str, list[str]] = {}
    for rule in rules:
        for technique in rule.attack_techniques:
            rule_map.setdefault(technique, []).append(rule.title)

    techniques = sorted(observed | set(rule_map))
    return [
        CoverageRow(
            technique=technique,
            observed=technique in observed,
            rule_count=len(rule_map.get(technique, [])),
            rules=sorted(rule_map.get(technique, [])),
        )
        for technique in techniques
    ]


def detection_gaps(findings: list[Finding], rules: list[DetectionRule]) -> list[CoverageRow]:
    return [row for row in build_coverage(findings, rules) if row.observed and not row.covered]


def render_coverage(rows: list[CoverageRow]) -> str:
    lines = [
        "SOCMind Detection Coverage",
        "==========================",
        "Technique     Observed  Covered  Rules",
    ]
    if not rows:
        lines.append("(no ATT&CK techniques found)")
        return "\n".join(lines)
    for row in rows:
        names = "; ".join(row.rules) if row.rules else "-"
        lines.append(
            f"{row.technique:<13} {'yes' if row.observed else 'no':<9} "
            f"{'yes' if row.covered else 'no':<8} {names}"
        )
    return "\n".join(lines)
