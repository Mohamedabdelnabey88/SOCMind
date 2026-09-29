from __future__ import annotations

from dataclasses import asdict

from .engine import analyze
from .graph import build_graph
from .hypothesis import generate_hypotheses
from .ioc import extract_iocs
from .models import Event
from .playbooks import select_playbook
from .triage import triage


def build_dashboard_payload(events: list[Event], *, case_id: str) -> dict:
    findings = analyze(events)
    nodes, edges = build_graph(events)
    techniques = sorted({
        technique.split()[0]
        for finding in findings
        for technique in finding.techniques
    })

    finding_rows = []
    for finding in findings:
        evidence = sorted(finding.evidence, key=lambda item: item.timestamp)
        detected_at = evidence[-1].timestamp.isoformat() if evidence else None
        detection_source = evidence[-1].source if evidence else "socmind-detection"
        finding_rows.append({
            "title": finding.title,
            "severity": finding.severity,
            "score": finding.score,
            "rationale": finding.rationale,
            "techniques": finding.techniques,
            "triage": asdict(triage(finding)),
            "playbook": [asdict(step) for step in select_playbook(finding)],
            "detected_at": detected_at,
            "source": detection_source,
        })

    return {
        "case_id": case_id,
        "summary": {
            "events": len(events),
            "findings": len(findings),
            "critical_or_high": sum(
                1 for finding in findings if finding.severity.lower() in {"critical", "high"}
            ),
            "highest_score": max((finding.score for finding in findings), default=0),
            "hosts": len({event.host for event in events}),
            "users": len({event.user for event in events if event.user}),
            "techniques": len(techniques),
        },
        "findings": finding_rows,
        "techniques": techniques,
        "iocs": [asdict(ioc) for ioc in extract_iocs(events)],
        "hypotheses": [asdict(item) for item in generate_hypotheses(findings)],
        "graph": {
            "nodes": [asdict(node) for node in nodes],
            "edges": [asdict(edge) for edge in edges],
        },
        "timeline": [
            {
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "event_id": event.event_id,
                "host": event.host,
                "user": event.user,
                "process": event.process,
                "parent_process": event.parent_process,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "command_line": event.command_line,
            }
            for event in sorted(events, key=lambda item: item.timestamp)
        ],
    }
