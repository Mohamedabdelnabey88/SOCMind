from __future__ import annotations

from datetime import datetime, timezone
import json


def _parse_timestamp(value) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _entry(
    timestamp,
    event_type: str,
    *,
    source: str,
    actor: str | None,
    detail: str,
    title: str,
    kind: str,
) -> dict:
    return {
        "timestamp": timestamp,
        "type": event_type,
        "source": source,
        "actor": actor,
        "detail": detail,
        "title": title,
        "kind": kind,
    }


def _json_detail(value) -> dict | None:
    try:
        payload = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _transition_target(detail: str) -> str | None:
    transition = str(detail or "").split(" | reason: ", 1)[0]
    if " -> " not in transition:
        return None
    return transition.split(" -> ", 1)[1].strip() or None


def build_unified_case_timeline(
    detail: dict,
    investigation: dict | None = None,
) -> list[dict]:
    """Build one deterministic operational timeline for a case.

    The timeline is a read model. Persistent actions remain sourced from the case
    audit trail; evidence/detection entries are derived from linked case evidence.
    """
    items: list[dict] = []
    case = detail.get("case") or {}
    audit_rows = detail.get("audit") or []

    alert_link_audits: dict[str, dict] = {}
    created_from_orchestration = False
    for audit in audit_rows:
        if audit.get("action") != "alert-linked":
            continue
        payload = _json_detail(audit.get("detail"))
        if not payload:
            continue
        alert_id = str(payload.get("alert_id") or "")
        if alert_id:
            alert_link_audits[alert_id] = {"audit": audit, "payload": payload}
        if payload.get("created_case"):
            created_from_orchestration = True

    opened_at = case.get("opened_at")
    if opened_at and not created_from_orchestration:
        items.append(_entry(
            opened_at,
            "case-created",
            source=str(case.get("source") or "case-store"),
            actor=None,
            detail=(
                f"Case opened with priority {case.get('priority', 'P3')} "
                f"from {case.get('source') or 'unknown source'}"
            ),
            title="Case created",
            kind="case",
        ))

    for alert in detail.get("alerts") or []:
        alert_id = str(alert.get("alert_id") or "")
        source = str(alert.get("source") or "unknown")
        items.append(_entry(
            alert.get("timestamp"),
            "alert-received",
            source=source,
            actor=None,
            detail=(
                f"{alert.get('title') or alert_id or 'Alert'} · "
                f"severity {alert.get('severity', '—')} · "
                f"priority {alert.get('priority', '—')} · "
                f"correlation {alert.get('correlation_score', 0)}"
            ),
            title=alert.get("title") or alert_id or "Alert received",
            kind="alert",
        ))

        linked = alert_link_audits.get(alert_id)
        if linked:
            audit = linked["audit"]
            payload = linked["payload"]
            created = bool(payload.get("created_case"))
            event_type = "case-created" if created else "alert-correlated"
            title = "Case created from alert" if created else "Alert correlated"
            score = int(payload.get("correlation_score") or 0)
            reasons = payload.get("correlation_reasons") or []
            reason_labels = [
                str(item.get("detail") or item.get("reason") or "").strip()
                for item in reasons
                if isinstance(item, dict)
            ]
            explanation = "; ".join(x for x in reason_labels if x)
            correlation_detail = f"Alert {alert_id} · correlation score {score}"
            if explanation:
                correlation_detail += f" · {explanation}"
            items.append(_entry(
                audit.get("timestamp"),
                event_type,
                source=source,
                actor=audit.get("actor"),
                detail=correlation_detail,
                title=title,
                kind="case" if created else "case-action",
            ))

    for collection in detail.get("evidence_collections") or []:
        status = str(collection.get("status") or "unknown")
        event_type = (
            "evidence-collected"
            if status == "completed"
            else "evidence-collection-failed"
        )
        items.append(_entry(
            collection.get("completed_at") or collection.get("started_at"),
            event_type,
            source=str(collection.get("provider") or "evidence-collector"),
            actor="socmind-evidence-collector",
            detail=(
                f"{collection.get('source_ref') or 'unknown source'} · "
                f"{collection.get('event_count', 0)} event(s) · {status}"
            ),
            title=f"Evidence collection · {status}",
            kind="evidence-collection",
        ))

    for requirement in detail.get("evidence_requirements") or []:
        items.append(_entry(
            requirement.get("created_at"),
            "evidence-requirement",
            source=str(requirement.get("source") or "case"),
            actor=requirement.get("requested_by"),
            detail=(
                f"{requirement.get('title') or requirement.get('key') or 'Evidence requirement'} "
                f"· {requirement.get('status') or 'required'}"
            ),
            title="Evidence requirement",
            kind="case-action",
        ))
        if (
            requirement.get("updated_at")
            and requirement.get("updated_at") != requirement.get("created_at")
        ):
            items.append(_entry(
                requirement.get("updated_at"),
                "evidence-requirement-updated",
                source=str(requirement.get("source") or "case"),
                actor=requirement.get("assigned_to") or requirement.get("requested_by"),
                detail=(
                    f"{requirement.get('title') or requirement.get('key') or 'Evidence requirement'} "
                    f"· {requirement.get('status') or 'unknown'}"
                ),
                title="Evidence requirement updated",
                kind="case-action",
            ))

    note_audit_ids: set[tuple[str, str]] = set()
    for note in detail.get("notes") or []:
        key = (str(note.get("created_at") or ""), str(note.get("author") or ""))
        note_audit_ids.add(key)
        items.append(_entry(
            note.get("created_at"),
            "note",
            source="analyst",
            actor=note.get("author"),
            detail=str(note.get("text") or ""),
            title="Analyst note",
            kind="analyst-note",
        ))

    for audit in audit_rows:
        action = str(audit.get("action") or "")
        actor = audit.get("actor")
        timestamp = audit.get("timestamp")
        raw_detail = str(audit.get("detail") or "")

        if action == "alert-linked":
            continue
        if action in {"evidence-collected", "evidence-collection-failed"}:
            continue
        if action.startswith("evidence-requirement-"):
            continue
        if action == "note-added" and (str(timestamp or ""), str(actor or "")) in note_audit_ids:
            continue

        event_type = "case-action"
        title = action or "Case action"
        source = "case-audit"

        if action == "acknowledged":
            event_type = "analyst-acknowledged"
            title = "Case acknowledged"
        elif action == "assigned":
            event_type = "assignment"
            title = "Case assignment"
        elif action == "state-transition":
            target = _transition_target(raw_detail)
            if target == "contained":
                event_type = "containment"
                title = "Case contained"
            elif target in {"resolved", "false-positive"}:
                event_type = "resolution"
                title = "Case resolved" if target == "resolved" else "False-positive disposition"
            else:
                event_type = "state-transition"
                title = "Case state transition"
        elif action in {"escalated", "escalation"}:
            event_type = "escalation"
            title = "Case escalation"
        elif action in {"detection-feedback", "detection-feedback-recorded"}:
            event_type = "detection-feedback"
            title = "Detection feedback"

        items.append(_entry(
            timestamp,
            event_type,
            source=source,
            actor=actor,
            detail=raw_detail,
            title=title,
            kind="case-action",
        ))

    if investigation and not investigation.get("error"):
        detection_keys: set[tuple[str, str]] = set()
        for finding in investigation.get("findings") or []:
            timestamp = finding.get("detected_at")
            if not timestamp:
                continue
            title = str(finding.get("title") or "Detection")
            key = (str(timestamp), title)
            if key in detection_keys:
                continue
            detection_keys.add(key)
            techniques = ", ".join(finding.get("techniques") or [])
            detail_text = (
                f"{title} · severity {finding.get('severity', 'unknown')} · "
                f"score {finding.get('score', 0)}"
            )
            if techniques:
                detail_text += f" · ATT&CK {techniques}"
            items.append(_entry(
                timestamp,
                "detection-event",
                source=str(finding.get("source") or "socmind-detection"),
                actor="socmind-detection-engine",
                detail=detail_text,
                title=title,
                kind="detection",
            ))

        for event in investigation.get("timeline") or []:
            items.append(_entry(
                event.get("timestamp"),
                "evidence-event",
                source=str(event.get("source") or "evidence"),
                actor=None,
                detail=str(
                    event.get("command_line")
                    or event.get("process")
                    or event.get("dst_ip")
                    or event.get("src_ip")
                    or event.get("user")
                    or ""
                ),
                title=(
                    f"{event.get('host') or 'unknown'} · "
                    f"{event.get('event_id') or 'event'}"
                ),
                kind="evidence",
            ))

    items.sort(key=lambda item: (
        _parse_timestamp(item.get("timestamp")),
        str(item.get("type") or ""),
        str(item.get("title") or ""),
    ))
    return items
