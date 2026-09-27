from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Event


@dataclass(slots=True)
class DetectionRule:
    id: str
    title: str
    status: str
    level: str
    logsource: dict[str, Any]
    detection: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    source_path: str | None = None

    @property
    def attack_techniques(self) -> list[str]:
        values: list[str] = []
        for tag in self.tags:
            lower = tag.lower()
            if lower.startswith("attack.t"):
                values.append(tag.split(".", 1)[1].upper())
        return sorted(set(values))


def load_rule(path: str | Path) -> DetectionRule:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "Sigma YAML support requires PyYAML. Install with: pip install 'socmind[sigma]'"
        ) from exc

    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Rule must be a mapping: {source}")

    required = ("title", "detection")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ValueError(f"Missing required Sigma field(s): {', '.join(missing)}")

    return DetectionRule(
        id=str(raw.get("id", source.stem)),
        title=str(raw["title"]),
        status=str(raw.get("status", "experimental")),
        level=str(raw.get("level", "medium")),
        logsource=dict(raw.get("logsource") or {}),
        detection=dict(raw["detection"]),
        tags=[str(v) for v in (raw.get("tags") or [])],
        falsepositives=[str(v) for v in (raw.get("falsepositives") or [])],
        source_path=str(source),
    )


def load_rules(directory: str | Path) -> list[DetectionRule]:
    root = Path(directory)
    rules: list[DetectionRule] = []
    for path in sorted([*root.rglob("*.yml"), *root.rglob("*.yaml")]):
        rules.append(load_rule(path))
    return rules


def _get_field(event: Event, name: str) -> Any:
    aliases = {
        "EventID": event.event_id,
        "Computer": event.host,
        "User": event.user,
        "TargetUserName": event.user,
        "Image": event.process,
        "ParentImage": event.parent_process,
        "CommandLine": event.command_line,
        "SourceIp": event.src_ip,
        "IpAddress": event.src_ip,
        "DestinationIp": event.dst_ip,
    }
    if name in aliases:
        return aliases[name]
    return event.data.get(name)


def _match_scalar(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False
    actual_text = str(actual).lower()
    expected_text = str(expected).lower()
    if modifier == "contains":
        return expected_text in actual_text
    if modifier == "startswith":
        return actual_text.startswith(expected_text)
    if modifier == "endswith":
        return actual_text.endswith(expected_text)
    return actual_text == expected_text


def _match_value(actual: Any, expected: Any, modifier: str | None) -> bool:
    candidates = expected if isinstance(expected, list) else [expected]
    return any(_match_scalar(actual, candidate, modifier) for candidate in candidates)


def match_selection(event: Event, selection: dict[str, Any]) -> bool:
    for raw_field, expected in selection.items():
        parts = raw_field.split("|")
        field = parts[0]
        modifiers = parts[1:]
        supported = {"contains", "startswith", "endswith"}
        unknown = [m for m in modifiers if m not in supported]
        if unknown:
            raise ValueError(f"Unsupported Sigma modifier(s): {', '.join(unknown)}")
        modifier = modifiers[0] if modifiers else None
        if not _match_value(_get_field(event, field), expected, modifier):
            return False
    return True


def match_rule(rule: DetectionRule, event: Event) -> bool:
    detection = rule.detection
    condition = str(detection.get("condition", "")).strip()
    selections = {
        key: value
        for key, value in detection.items()
        if key != "condition" and isinstance(value, dict)
    }
    if not selections:
        return False

    if condition in selections:
        return match_selection(event, selections[condition])

    # Supported portable subset: "selection1 or selection2" / "and".
    if " or " in condition:
        names = [part.strip() for part in condition.split(" or ")]
        return any(name in selections and match_selection(event, selections[name]) for name in names)
    if " and " in condition:
        names = [part.strip() for part in condition.split(" and ")]
        return all(name in selections and match_selection(event, selections[name]) for name in names)

    raise ValueError(
        f"Unsupported Sigma condition in {rule.title!r}: {condition!r}. "
        "SOCMind v0.5 supports a named selection or simple AND/OR between named selections."
    )


def evaluate_rule(rule: DetectionRule, events: list[Event]) -> list[Event]:
    return [event for event in events if match_rule(rule, event)]
