from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .models import Event


@dataclass(frozen=True, slots=True)
class AlertRecord:
    alert_id: str
    source: str
    timestamp: datetime
    title: str
    severity: int
    host: str
    user: str | None = None
    process: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    technique: str | None = None
    rule_id: str | None = None
    raw_reference: str | None = None


@dataclass(frozen=True, slots=True)
class CorrelationReason:
    key: str
    weight: int
    detail: str


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    related: bool
    score: int
    reasons: list[CorrelationReason]


@dataclass(frozen=True, slots=True)
class EvidenceWindow:
    alert_id: str
    start: str
    end: str
    events: list[Event]


def alert_priority(severity: int) -> str:
    level = max(0, min(int(severity), 15))
    if level >= 12:
        return "P1"
    if level >= 7:
        return "P2"
    return "P3"


def case_id_for_alert(alert: AlertRecord) -> str:
    digest = hashlib.sha256(
        f"{alert.source}|{alert.alert_id}".encode("utf-8")
    ).hexdigest()[:32].upper()
    return f"INC-{alert.timestamp:%Y%m%d}-{digest}"


def alert_fingerprint(alert: AlertRecord) -> str:
    normalized = "|".join(
        [
            alert.source.lower(),
            (alert.rule_id or "").lower(),
            alert.host.lower(),
            (alert.user or "").lower(),
            (alert.process or "").lower(),
            (alert.src_ip or "").lower(),
            (alert.dst_ip or "").lower(),
        ]
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _known_context(value: str | None) -> bool:
    return isinstance(value, str) and value.strip().lower() not in {
        "", "unknown", "none", "null", "n/a", "-", "wazuh-host", "elastic-host",
    }


def _fallback_identity(event: Event, provider: str) -> str:
    payload = asdict(event)
    payload["timestamp"] = event.timestamp.isoformat()
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return provider + "-fallback-" + hashlib.sha256(serialized.encode()).hexdigest()


def correlate_alerts(
    left: AlertRecord,
    right: AlertRecord,
    *,
    window_minutes: int = 15,
    threshold: int = 55,
) -> CorrelationResult:
    if abs((left.timestamp - right.timestamp).total_seconds()) > window_minutes * 60:
        return CorrelationResult(False, 0, [])

    score = 0
    reasons: list[CorrelationReason] = []

    def add(key: str, weight: int, detail: str):
        nonlocal score
        score += weight
        reasons.append(CorrelationReason(key, weight, detail))

    if _known_context(left.host) and _known_context(right.host) and left.host.lower() == right.host.lower():
        add("same-host", 30, f"Same host: {left.host}")
    if _known_context(left.user) and _known_context(right.user) and left.user.lower() == right.user.lower():
        add("same-user", 20, f"Same user: {left.user}")
    if _known_context(left.process) and _known_context(right.process) and left.process.lower() == right.process.lower():
        add("same-process", 15, f"Same process: {left.process}")
    if _known_context(left.src_ip) and _known_context(right.src_ip) and left.src_ip == right.src_ip:
        add("same-source-ip", 15, f"Same source IP: {left.src_ip}")
    if _known_context(left.dst_ip) and _known_context(right.dst_ip) and left.dst_ip == right.dst_ip:
        add("same-destination-ip", 10, f"Same destination IP: {left.dst_ip}")
    if _known_context(left.rule_id) and _known_context(right.rule_id) and left.rule_id == right.rule_id:
        add("same-rule", 10, f"Same rule: {left.rule_id}")
    if _known_context(left.technique) and _known_context(right.technique) and left.technique == right.technique:
        add("same-technique", 15, f"Same ATT&CK technique: {left.technique}")

    score = min(score, 100)
    keys = {item.key for item in reasons}
    context_anchors = {
        "same-user",
        "same-process",
        "same-source-ip",
        "same-destination-ip",
    }
    if "same-host" in keys:
        anchor_safe = bool(keys & context_anchors)
    else:
        anchor_safe = len(keys & context_anchors) >= 2

    return CorrelationResult(
        score >= threshold and anchor_safe,
        score,
        reasons,
    )


def collect_evidence_window(
    alert: AlertRecord,
    events: Iterable[Event],
    *,
    before_minutes: int = 15,
    after_minutes: int = 15,
) -> EvidenceWindow:
    start = alert.timestamp - timedelta(minutes=max(0, before_minutes))
    end = alert.timestamp + timedelta(minutes=max(0, after_minutes))
    selected = [
        event
        for event in events
        if start <= event.timestamp <= end
        and (
            (_known_context(alert.host) and _known_context(event.host) and event.host.lower() == alert.host.lower())
            or (
                alert.user
                and event.user
                and event.user.lower() == alert.user.lower()
            )
            or (
                alert.src_ip
                and event.src_ip
                and event.src_ip == alert.src_ip
            )
            or (
                alert.dst_ip
                and event.dst_ip
                and event.dst_ip == alert.dst_ip
            )
        )
    ]
    selected.sort(key=lambda item: item.timestamp)
    return EvidenceWindow(
        alert_id=alert.alert_id,
        start=start.isoformat(),
        end=end.isoformat(),
        events=selected,
    )



def _elastic_severity(source: dict) -> int:
    raw = source.get("kibana.alert.severity")
    mapping = {"low": 3, "medium": 7, "high": 10, "critical": 13}
    if isinstance(raw, str) and raw.lower() in mapping:
        return mapping[raw.lower()]

    risk = source.get("kibana.alert.risk_score")
    try:
        risk_value = float(risk)
    except (TypeError, ValueError):
        risk_value = None
    if risk_value is not None:
        if risk_value >= 74:
            return 13
        if risk_value >= 48:
            return 10
        if risk_value >= 22:
            return 7
        return 3

    rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
    signal = source.get("signal") if isinstance(source.get("signal"), dict) else {}
    signal_rule = signal.get("rule") if isinstance(signal.get("rule"), dict) else {}
    severity_raw = rule.get("severity") or signal_rule.get("severity")
    try:
        return int(severity_raw or 0)
    except (TypeError, ValueError):
        return 0


def _elastic_technique(source: dict) -> str | None:
    threat = source.get("kibana.alert.rule.threat")
    if isinstance(threat, list):
        for item in threat:
            if not isinstance(item, dict):
                continue
            techniques = item.get("technique")
            if isinstance(techniques, list):
                for technique in techniques:
                    if isinstance(technique, dict) and technique.get("id"):
                        return str(technique["id"]).upper()

    tags = source.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return next(
        (str(item).upper().replace("ATTACK.", "") for item in tags if str(item).lower().startswith("attack.t")),
        None,
    )

def alert_from_event(event: Event) -> AlertRecord:
    data = event.data or {}
    if event.source == "wazuh":
        severity = int(data.get("wazuh_rule_level") or 0)
        rule_id = str(data.get("wazuh_rule_id") or event.event_id)
        title = str(data.get("wazuh_rule_description") or f"Wazuh alert {rule_id}")
        technique = None
        raw = data.get("raw")
        alert_id = None
        if isinstance(raw, dict):
            alert_id = raw.get("id")
            raw_rule = raw.get("rule") or {}
            groups = raw_rule.get("groups") or []
            mitre = raw_rule.get("mitre") if isinstance(raw_rule.get("mitre"), dict) else {}
            mitre_ids = mitre.get("id") or []
            if isinstance(mitre_ids, str):
                mitre_ids = [mitre_ids]
            technique = next(
                (str(item).upper() for item in mitre_ids if str(item).upper().startswith("T")),
                None,
            ) or next(
                (str(item).upper().replace("ATTACK.", "") for item in groups if str(item).lower().startswith("attack.t")),
                None,
            )
        return AlertRecord(
            alert_id=str(alert_id or _fallback_identity(event, "wazuh")),
            source="wazuh",
            timestamp=event.timestamp,
            title=title,
            severity=severity,
            host=event.host,
            user=event.user,
            process=event.process,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            technique=technique,
            rule_id=rule_id,
        )

    ecs = data.get("ecs") if isinstance(data.get("ecs"), dict) else {}
    rule = ecs.get("rule") if isinstance(ecs.get("rule"), dict) else {}

    severity = _elastic_severity(ecs)
    rule_id = str(
        ecs.get("kibana.alert.rule.rule_id")
        or ecs.get("kibana.alert.rule.uuid")
        or rule.get("id")
        or event.event_id
    )
    title = str(
        ecs.get("kibana.alert.rule.name")
        or rule.get("name")
        or f"Elastic alert {rule_id}"
    )
    technique = _elastic_technique(ecs)
    alert_id = str(
        data.get("elastic_id")
        or ecs.get("_id")
        or _fallback_identity(event, "elastic")
    )
    return AlertRecord(
        alert_id=alert_id,
        source="elastic",
        timestamp=event.timestamp,
        title=title,
        severity=severity,
        host=event.host,
        user=event.user,
        process=event.process,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        technique=technique,
        rule_id=rule_id,
    )


def correlation_payload(result: CorrelationResult) -> dict:
    return {
        "related": result.related,
        "score": result.score,
        "reasons": [asdict(item) for item in result.reasons],
    }


def alert_payload(alert: AlertRecord) -> dict:
    payload = asdict(alert)
    payload["timestamp"] = alert.timestamp.isoformat()
    payload["priority"] = alert_priority(alert.severity)
    payload["fingerprint"] = alert_fingerprint(alert)
    return payload
