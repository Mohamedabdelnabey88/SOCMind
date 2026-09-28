from __future__ import annotations

from .command_center import command_center_snapshot


def render_shift_brief(command_snapshot: dict, lead_snapshot: dict) -> str:
    cs = command_snapshot.get("summary", {})
    ls = lead_snapshot.get("summary", {})

    lines = [
        "# SOCMind Shift Brief",
        "",
        "## Operations",
        f"- Active cases: {cs.get('active', 0)}",
        f"- P1 active: {cs.get('p1_active', 0)}",
        f"- SLA breaches: {cs.get('sla_breached', 0)}",
        f"- Unassigned: {cs.get('unassigned', 0)}",
        f"- MTTA: {cs.get('mtta_minutes') if cs.get('mtta_minutes') is not None else '-'} minutes",
        f"- MTTR: {cs.get('mttr_minutes') if cs.get('mttr_minutes') is not None else '-'} minutes",
        "",
        "## Detection Health",
        f"- Rules loaded: {ls.get('rules', 0)}",
        f"- ATT&CK coverage: {ls.get('coverage_percent') if ls.get('coverage_percent') is not None else '-'}%",
        f"- Noisy rules: {ls.get('noisy_rules', 0)}",
        "",
        "## Priority Queue",
    ]

    queue = command_snapshot.get("queue", [])
    priority = sorted(
        queue,
        key=lambda item: (
            {"P1": 1, "P2": 2, "P3": 3}.get(item.get("priority"), 9),
            0 if item.get("sla") and item["sla"].get("breached") else 1,
        ),
    )
    for item in priority[:5]:
        sla = item.get("sla")
        sla_text = "closed"
        if sla:
            sla_text = "BREACHED" if sla.get("breached") else f"{sla.get('remaining_minutes')}m left"
        lines.append(
            f"- {item.get('priority')} | {item.get('case_id')} | "
            f"{item.get('state')} | {item.get('owner') or 'Unassigned'} | {sla_text}"
        )
    if not priority:
        lines.append("- No registered cases.")

    lines += ["", "## Noisy Detections"]
    noisy = [row for row in lead_snapshot.get("detection_health", []) if row.get("noisy")]
    for row in noisy[:5]:
        lines.append(
            f"- {row['rule_id']} | FP={row['false_positive_rate']:.0%} | samples={row['sample_size']}"
        )
    if not noisy:
        lines.append("- No rule crossed the noisy-detection threshold.")

    lines += ["", "## Top Targeted Users"]
    for item in lead_snapshot.get("top_users", [])[:5]:
        lines.append(f"- {item['user']}: {item['events']} events")
    if not lead_snapshot.get("top_users"):
        lines.append("- No user telemetry available.")

    lines += ["", "## Top Hosts"]
    for item in lead_snapshot.get("top_hosts", [])[:5]:
        lines.append(f"- {item['host']}: {item['events']} events")
    if not lead_snapshot.get("top_hosts"):
        lines.append("- No host telemetry available.")

    return "\n".join(lines)
