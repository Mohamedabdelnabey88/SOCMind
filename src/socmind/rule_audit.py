from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .detections import DetectionRule, load_rules


ATTACK_TAG = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.I)
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {
    "experimental",
    "test",
    "stable",
    "deprecated",
    "unsupported",
}


@dataclass(frozen=True, slots=True)
class RuleAuditIssue:
    severity: str
    rule_id: str
    title: str
    code: str
    message: str
    source_path: str | None


@dataclass(frozen=True, slots=True)
class RuleAuditResult:
    rules: int
    errors: int
    warnings: int
    passed: int
    production_ready: bool
    issues: list[RuleAuditIssue]


def _condition_names(rule: DetectionRule) -> tuple[set[str], str]:
    detection = rule.detection
    selections = {
        key
        for key, value in detection.items()
        if key != "condition" and isinstance(value, dict)
    }
    condition = str(detection.get("condition", "")).strip()
    return selections, condition


def audit_rule_pack(directory: str | Path) -> RuleAuditResult:
    rules = load_rules(directory)
    issues: list[RuleAuditIssue] = []

    ids: dict[str, list[DetectionRule]] = {}
    for rule in rules:
        ids.setdefault(rule.id, []).append(rule)

    for rule_id, duplicates in ids.items():
        if len(duplicates) > 1:
            for rule in duplicates:
                issues.append(
                    RuleAuditIssue(
                        "error",
                        rule.id,
                        rule.title,
                        "duplicate-id",
                        f"Rule ID {rule_id!r} appears {len(duplicates)} times.",
                        rule.source_path,
                    )
                )

    for rule in rules:
        def add(severity: str, code: str, message: str) -> None:
            issues.append(
                RuleAuditIssue(
                    severity,
                    rule.id,
                    rule.title,
                    code,
                    message,
                    rule.source_path,
                )
            )

        if not rule.id.strip():
            add("error", "missing-id", "Rule ID is empty.")
        if not rule.title.strip():
            add("error", "missing-title", "Rule title is empty.")
        if rule.level.lower() not in VALID_LEVELS:
            add(
                "error",
                "invalid-level",
                f"Unsupported level {rule.level!r}.",
            )
        if rule.status.lower() not in VALID_STATUSES:
            add(
                "warning",
                "nonstandard-status",
                f"Status {rule.status!r} is outside the supported quality vocabulary.",
            )
        if not rule.logsource:
            add(
                "warning",
                "missing-logsource",
                "Rule has no logsource metadata.",
            )
        if not rule.falsepositives:
            add(
                "warning",
                "missing-falsepositives",
                "Rule does not document expected false positives.",
            )

        attack_tags = [
            tag
            for tag in rule.tags
            if tag.lower().startswith("attack.")
        ]
        invalid_attack_tags = [
            tag for tag in attack_tags if not ATTACK_TAG.match(tag)
        ]
        if invalid_attack_tags:
            add(
                "error",
                "invalid-attack-tag",
                "Invalid ATT&CK tag(s): " + ", ".join(invalid_attack_tags),
            )
        if not rule.attack_techniques:
            add(
                "warning",
                "missing-attack-mapping",
                "Rule has no ATT&CK technique mapping.",
            )

        selections, condition = _condition_names(rule)
        if not selections:
            add(
                "error",
                "missing-selection",
                "Detection contains no mapping selections.",
            )
        if not condition:
            add(
                "error",
                "missing-condition",
                "Detection condition is empty.",
            )
        elif " or " in condition:
            names = [part.strip() for part in condition.split(" or ")]
            missing = [name for name in names if name not in selections]
            if missing:
                add(
                    "error",
                    "unknown-condition-selection",
                    "Condition references unknown selection(s): "
                    + ", ".join(missing),
                )
        elif " and " in condition:
            names = [part.strip() for part in condition.split(" and ")]
            missing = [name for name in names if name not in selections]
            if missing:
                add(
                    "error",
                    "unknown-condition-selection",
                    "Condition references unknown selection(s): "
                    + ", ".join(missing),
                )
        elif condition not in selections:
            add(
                "error",
                "unsupported-condition",
                (
                    f"Condition {condition!r} is outside SOCMind's supported "
                    "portable Sigma subset."
                ),
            )

    errors = sum(1 for issue in issues if issue.severity == "error")
    warnings = sum(1 for issue in issues if issue.severity == "warning")
    failing_rule_ids = {issue.rule_id for issue in issues if issue.severity == "error"}
    return RuleAuditResult(
        rules=len(rules),
        errors=errors,
        warnings=warnings,
        passed=max(0, len(rules) - len(failing_rule_ids)),
        production_ready=bool(rules) and errors == 0,
        issues=issues,
    )


def rule_audit_payload(directory: str | Path) -> dict:
    result = audit_rule_pack(directory)
    return {
        "rules": result.rules,
        "errors": result.errors,
        "warnings": result.warnings,
        "passed": result.passed,
        "production_ready": result.production_ready,
        "issues": [asdict(issue) for issue in result.issues],
    }


def render_rule_audit(directory: str | Path) -> str:
    result = audit_rule_pack(directory)
    lines = [
        "SOCMind Detection Rule Pack Audit",
        "=================================",
        f"rules={result.rules}",
        f"errors={result.errors}",
        f"warnings={result.warnings}",
        f"production_ready={str(result.production_ready).lower()}",
        "",
    ]
    if not result.issues:
        lines.append("No rule quality issues found.")
    else:
        for issue in result.issues:
            lines.append(
                f"[{issue.severity.upper()}] {issue.rule_id} | "
                f"{issue.code} | {issue.message}"
            )
    return "\n".join(lines)
