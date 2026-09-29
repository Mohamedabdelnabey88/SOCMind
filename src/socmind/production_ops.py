from __future__ import annotations

import hashlib
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
    ).hexdigest()[:8].upper()
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

    if left.host and right.host and left.host.lower() == right.host.lower():
        add("same-host", 30, f"Same host: {left.host}")
    if left.user and right.user and left.user.lower() == right.user.lower():
        add("same-user", 20, f"Same user: {left.user}")
    if left.process and right.process and left.process.lower() == right.process.lower():
        add("same-process", 15, f"Same process: {left.process}")
    if left.src_ip and right.src_ip and left.src_ip == right.src_ip:
        add("same-source-ip", 15, f"Same source IP: {left.src_ip}")
    if left.dst_ip and right.dst_ip and left.dst_ip == right.dst_ip:
        add("same-destination-ip", 10, f"Same destination IP: {left.dst_ip}")
    if left.rule_id and right.rule_id and left.rule_id == right.rule_id:
        add("same-rule", 10, f"Same rule: {left.rule_id}")
    if left.technique and right.technique and left.technique == right.technique:
        add("same-technique", 15, f"Same ATT&CK technique: {left.technique}")

    score = min(score, 100)
    return CorrelationResult(score >= threshold, score, reasons)


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
            event.host.lower() == alert.host.lower()
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
            groups = (raw.get("rule") or {}).get("groups") or []
            technique = next(
                (str(item).upper() for item in groups if str(item).lower().startswith("attack.t")),
                None,
            )
        return AlertRecord(
            alert_id=str(alert_id or f"wazuh-{rule_id}-{int(event.timestamp.timestamp())}"),
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
    signal = ecs.get("signal") if isinstance(ecs.get("signal"), dict) else {}
    severity_raw = (
        rule.get("severity")
        or signal.get("rule", {}).get("severity") if isinstance(signal.get("rule"), dict) else None
    )
    try:
        severity = int(severity_raw or 0)
    except (TypeError, ValueError):
        severity = 0

    rule_id = str(rule.get("id") or event.event_id)
    title = str(rule.get("name") or f"Elastic alert {rule_id}")
    tags = ecs.get("tags") or []
    technique = next(
        (str(item).upper() for item in tags if str(item).lower().startswith("attack.t")),
        None,
    )
    alert_id = str(ecs.get("_id") or f"elastic-{rule_id}-{int(event.timestamp.timestamp())}")
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
