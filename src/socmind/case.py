from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .graph import build_graph
from .hypothesis import generate_hypotheses
from .ioc import extract_iocs
from .models import Event, Finding
from .playbooks import select_playbook
from .triage import triage


def export_case(
    events: list[Event],
    findings: list[Finding],
    output: str | Path,
    *,
    case_id: str = "SOCMIND-CASE",
) -> None:
    nodes, edges = build_graph(events)
    hypotheses = generate_hypotheses(findings)

    payload = {
        "schema_version": "1.0",
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "events": len(events),
            "findings": len(findings),
            "highest_score": max((f.score for f in findings), default=0),
        },
        "findings": [],
        "hypotheses": [asdict(h) for h in hypotheses],
        "iocs": [asdict(i) for i in extract_iocs(events)],
        "graph": {
            "nodes": [asdict(n) for n in nodes],
            "edges": [asdict(e) for e in edges],
        },
    }

    for finding in findings:
        decision = triage(finding)
        payload["findings"].append({
            "title": finding.title,
            "severity": finding.severity,
            "score": finding.score,
            "rationale": finding.rationale,
            "techniques": finding.techniques,
            "triage": asdict(decision),
            "playbook": [asdict(step) for step in select_playbook(finding)],
        })

    Path(output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
