import argparse
import json
import os
from pathlib import Path

from .audit_chain import verify_chain
from .benchmark import run_benchmark
from .adapters import (
    parse_auditd,
    parse_auth_log,
    parse_elastic_ndjson,
    parse_elastic_hits,
    parse_evtx,
    parse_journald_json,
    parse_wazuh_alerts,
    wazuh_search_hits_to_events,
    parse_windows_event_xml,
)
from .case import export_case
from .audit import append_audit
from .case_workflow import assign, load_case, new_case, save_case, transition
from .coverage import build_coverage, detection_gaps, render_coverage
from .contradiction import contradiction_payload, render_contradictions
from .command_center import (
    acknowledge_case,
    add_case_note,
    assign_case,
    case_detail,
    command_center_snapshot,
    transition_case,
    upsert_case,
)
from .detections import evaluate_rule, load_rule, load_rules
from .demo import create_demo
from .detection_replay import detection_replay_payload, render_detection_replay
from .doctor import doctor_payload, run_doctor
from .enterprise_auth import trusted_proxy_headers
from .enterprise_ops import backup_sqlite, postgres_schema, render_retention, retention_scan
from .engine import analyze
from .enrichment import LocalIntelProvider, enrich_iocs
from .escalation import export_escalation_package
from .graph import render_mermaid
from .helptext import render_help
from .handoff import render_shift_handoff
from .hardening import security_payload, security_report, validate_web_binding
from .hypothesis import generate_hypotheses
from .integrations import ElasticClient, WazuhClient, integration_check
from .io import load_jsonl
from .lead_metrics import lead_snapshot
from .live_evidence import collect_case_evidence_postgres, collect_case_evidence_sqlite, collection_payload
from .evidence_integrity import verification_payload, verify_evidence_manifest
from .quality_gate import load_checklist, quality_payload, render_quality_review
from .ioc import extract_iocs
from .notes import append_note
from .orchestration import orchestrate_alert_postgres, orchestrate_alert_sqlite
from .production_ops import alert_from_event
from .process_tree import render_process_tree
from .postgres_store import initialize_postgres, postgres_health
from .provenance import fingerprint
from .regression import generate_regression_package
from .rbac import ROLE_PERMISSIONS
from .replay import replay_payload, render_replay
from .report import render_text
from .rule_tests import run_rule_test
from .similarity import render_similarity, similarity_payload
from .sla import evaluate_sla
from .shift_brief import render_shift_brief
from .timeline import render_timeline
from .threat_intel_live import MISPProvider, OpenCTIClient
from .tuning import load_dispositions, suggest_tuning
from .whatif import compare_rule_packs, render_what_if
from .workspace import build_workspace


def _events_to_jsonl(events, output: str) -> None:
    target = Path(output)
    with target.open("w", encoding="utf-8") as fh:
        for event in events:
            payload = {
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
                "data": event.data,
            }
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socmind",
        description="Cross-platform SOC Tier 1/2 investigation toolkit",
        epilog=(
            "Start here: socmind help getting-started\n"
            "Examples: socmind help triage | socmind help integrations | socmind demo-init -o socmind-demo"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="SOCMind 1.6.0")
    sub = parser.add_subparsers(dest="command", required=True)

    help_cmd = sub.add_parser("help", help="Show task-oriented SOCMind help")
    help_cmd.add_argument("topic", nargs="?")

    doctor_cmd = sub.add_parser("doctor", help="Check local SOCMind installation and optional features")
    doctor_cmd.add_argument("--json", action="store_true")

    analyze_cmd = sub.add_parser("analyze", help="Analyze normalized JSONL security events")
    analyze_cmd.add_argument("path")
    analyze_cmd.add_argument("--timeline", action="store_true")
    analyze_cmd.add_argument("--iocs", action="store_true")
    analyze_cmd.add_argument("--graph", action="store_true")
    analyze_cmd.add_argument("--process-tree", action="store_true")
    analyze_cmd.add_argument("--hypotheses", action="store_true")
    analyze_cmd.add_argument("--case-output")
    analyze_cmd.add_argument("--case-id", default="SOCMIND-CASE")

    ingest = sub.add_parser("ingest", help="Normalize raw/SIEM telemetry")
    ingest.add_argument(
        "format",
        choices=[
            "linux-auth",
            "journald",
            "auditd",
            "windows-xml",
            "windows-evtx",
            "wazuh",
            "elastic",
        ],
    )
    ingest.add_argument("path")
    ingest.add_argument("-o", "--output", required=True)
    ingest.add_argument("--host", default="linux-host")
    ingest.add_argument("--year", type=int)

    timeline_cmd = sub.add_parser("timeline")
    timeline_cmd.add_argument("path")

    ioc_cmd = sub.add_parser("iocs")
    ioc_cmd.add_argument("path")
    ioc_cmd.add_argument("--json", action="store_true")

    graph_cmd = sub.add_parser("graph")
    graph_cmd.add_argument("path")

    case_cmd = sub.add_parser("case")
    case_cmd.add_argument("path")
    case_cmd.add_argument("-o", "--output", required=True)
    case_cmd.add_argument("--case-id", default="SOCMIND-CASE")

    detect_cmd = sub.add_parser("detect", help="Evaluate one Sigma-style rule")
    detect_cmd.add_argument("rule")
    detect_cmd.add_argument("events")

    coverage_cmd = sub.add_parser("coverage", help="Show ATT&CK detection coverage")
    coverage_cmd.add_argument("events")
    coverage_cmd.add_argument("--rules", default="detections")

    gaps_cmd = sub.add_parser("gaps", help="Show observed ATT&CK techniques without local rules")
    gaps_cmd.add_argument("events")
    gaps_cmd.add_argument("--rules", default="detections")

    rule_test_cmd = sub.add_parser("rule-test", help="Run one detection rule fixture")
    rule_test_cmd.add_argument("rule")
    rule_test_cmd.add_argument("fixture")

    tune_cmd = sub.add_parser("tune", help="Suggest conservative false-positive tuning")
    tune_cmd.add_argument("dispositions")
    tune_cmd.add_argument("--min-samples", type=int, default=5)

    enrich_cmd = sub.add_parser("enrich", help="Enrich extracted IOCs using configured providers")
    enrich_cmd.add_argument("events")
    enrich_cmd.add_argument("--local-intel", required=True)
    enrich_cmd.add_argument("--json", action="store_true")

    note_cmd = sub.add_parser("note", help="Append an analyst note/disposition")
    note_cmd.add_argument("journal")
    note_cmd.add_argument("--case-id", required=True)
    note_cmd.add_argument("--author", required=True)
    note_cmd.add_argument("--text", required=True)
    note_cmd.add_argument("--disposition")

    escalate_cmd = sub.add_parser("escalate", help="Export a Tier 2/IR handoff package")
    escalate_cmd.add_argument("events")
    escalate_cmd.add_argument("--case-id", required=True)
    escalate_cmd.add_argument("-o", "--output", required=True)

    web_cmd = sub.add_parser("web", help="Launch the local investigation dashboard")
    web_cmd.add_argument("events", help="Normalized JSONL investigation file")
    web_cmd.add_argument("--case-id", default="SOCMIND-WEB")
    web_cmd.add_argument("--host", default="127.0.0.1")
    web_cmd.add_argument("--port", type=int, default=8765)
    web_cmd.add_argument("--command-db", help="Optional SQLite SOC command-center database")
    web_cmd.add_argument("--postgres-dsn", help="Optional PostgreSQL enterprise case-store DSN; prefer SOCMIND_POSTGRES_DSN")
    web_cmd.add_argument("--rules", default="detections")
    web_cmd.add_argument("--dispositions")
    web_cmd.add_argument("--proposed-rules", help="Optional proposed rule pack for IRE what-if comparison")
    web_cmd.add_argument("--quality-checklist", help="Optional analyst checklist JSON for IRE quality gate")
    web_cmd.add_argument("--api-token", help="Optional API token; prefer SOCMIND_API_TOKEN environment variable")
    web_cmd.add_argument("--auth-mode", choices=["local-token", "trusted-proxy"], default="local-token")
    web_cmd.add_argument("--api-token-role", choices=sorted(ROLE_PERMISSIONS), default="admin")
    web_cmd.add_argument("--enterprise-audit", help="Optional tamper-evident enterprise audit JSONL path")
    web_cmd.add_argument("--allow-unsafe-remote", action="store_true", help="Explicitly allow non-loopback bind without token (isolated lab only)")

    case_init = sub.add_parser("case-init", help="Create an operational SOC case record")
    case_init.add_argument("output")
    case_init.add_argument("--case-id", required=True)
    case_init.add_argument("--priority", choices=["P1", "P2", "P3"], default="P3")
    case_init.add_argument("--owner")

    case_assign = sub.add_parser("case-assign", help="Assign a case to an analyst")
    case_assign.add_argument("case_file")
    case_assign.add_argument("--owner", required=True)

    case_move = sub.add_parser("case-transition", help="Move a case through the SOC lifecycle")
    case_move.add_argument("case_file")
    case_move.add_argument("--state", required=True)

    sla_cmd = sub.add_parser("sla", help="Evaluate the case response SLA")
    sla_cmd.add_argument("case_file")

    evidence_cmd = sub.add_parser("evidence", help="Fingerprint evidence with SHA-256")
    evidence_cmd.add_argument("path")

    evidence_verify = sub.add_parser(
        "evidence-verify",
        help="Verify a SOCMind evidence package against its SHA-256 integrity manifest",
    )
    evidence_verify.add_argument("path", help="Evidence JSONL file")
    evidence_verify.add_argument("--manifest", help="Optional manifest path; defaults to <evidence>.manifest.json")
    evidence_verify.add_argument("--json", action="store_true")

    handoff_cmd = sub.add_parser("handoff", help="Create a shift handoff summary")
    handoff_cmd.add_argument("events")
    handoff_cmd.add_argument("--case-id", required=True)
    handoff_cmd.add_argument("-o", "--output")

    audit_cmd = sub.add_parser("audit", help="Append an analyst action to the case audit trail")
    audit_cmd.add_argument("journal")
    audit_cmd.add_argument("--case-id", required=True)
    audit_cmd.add_argument("--actor", required=True)
    audit_cmd.add_argument("--action", required=True)
    audit_cmd.add_argument("--detail", required=True)

    investigate_cmd = sub.add_parser("investigate", help="Build a complete SOC investigation workspace")
    investigate_cmd.add_argument("events")
    investigate_cmd.add_argument("-o", "--output", required=True)
    investigate_cmd.add_argument("--case-id", required=True)
    investigate_cmd.add_argument("--priority", choices=["P1", "P2", "P3"], default="P2")
    investigate_cmd.add_argument("--owner")

    command_register = sub.add_parser("command-register", help="Register/update a case in the SOC command center")
    command_register.add_argument("database")
    command_register.add_argument("case_file")
    command_register.add_argument("--source")
    command_register.add_argument("--title")
    command_register.add_argument("--events", help="Normalized JSONL evidence path for case detail")

    command_view = sub.add_parser("command-center", help="Show SOC queue, SLA and workload metrics")
    command_view.add_argument("database")
    command_view.add_argument("--json", action="store_true")

    command_ack = sub.add_parser("command-ack", help="Acknowledge a case and start MTTA tracking")
    command_ack.add_argument("database")
    command_ack.add_argument("case_id")

    command_assign = sub.add_parser("command-assign", help="Assign a registered case")
    command_assign.add_argument("database")
    command_assign.add_argument("case_id")
    command_assign.add_argument("--owner", required=True)
    command_assign.add_argument("--actor", default="cli-analyst")

    command_transition = sub.add_parser("command-transition", help="Transition a registered case")
    command_transition.add_argument("database")
    command_transition.add_argument("case_id")
    command_transition.add_argument("--state", required=True)
    command_transition.add_argument("--actor", default="cli-analyst")

    command_note = sub.add_parser("command-note", help="Add a note to a registered case")
    command_note.add_argument("database")
    command_note.add_argument("case_id")
    command_note.add_argument("--author", required=True)
    command_note.add_argument("--text", required=True)
    command_note.add_argument("--disposition")

    command_show = sub.add_parser("command-show", help="Show one registered case with notes/audit")
    command_show.add_argument("database")
    command_show.add_argument("case_id")

    lead_cmd = sub.add_parser("lead-health", help="Show SOC lead detection-health metrics")
    lead_cmd.add_argument("events")
    lead_cmd.add_argument("--rules", default="detections")
    lead_cmd.add_argument("--dispositions")
    lead_cmd.add_argument("--json", action="store_true")

    brief_cmd = sub.add_parser("shift-brief", help="Generate a SOC shift brief")
    brief_cmd.add_argument("database")
    brief_cmd.add_argument("events")
    brief_cmd.add_argument("--rules", default="detections")
    brief_cmd.add_argument("--dispositions")
    brief_cmd.add_argument("-o", "--output")

    demo_cmd = sub.add_parser("demo-init", help="Create a ready-to-run SOCMind demo environment")
    demo_cmd.add_argument("-o", "--output", default="socmind-demo")
    demo_cmd.add_argument("--windows-events", default="examples/attack_chain.jsonl")
    demo_cmd.add_argument("--linux-events", default="examples/linux_attack_chain.jsonl")

    wazuh_check = sub.add_parser("wazuh-check", help="Validate Wazuh Server API authentication/connectivity")
    wazuh_check.add_argument("url")
    wazuh_check.add_argument("--username")
    wazuh_check.add_argument("--insecure", action="store_true")

    wazuh_agents = sub.add_parser("wazuh-agents", help="List Wazuh agents through the live API")
    wazuh_agents.add_argument("url")
    wazuh_agents.add_argument("--username")
    wazuh_agents.add_argument("--limit", type=int, default=100)
    wazuh_agents.add_argument("--insecure", action="store_true")
    wazuh_agents.add_argument("--json", action="store_true")

    elastic_pull = sub.add_parser("elastic-pull", help="Pull live Elastic search hits to NDJSON")
    elastic_pull.add_argument("url")
    elastic_pull.add_argument("index")
    elastic_pull.add_argument("-o", "--output", required=True)
    elastic_pull.add_argument("--size", type=int, default=100)
    elastic_pull.add_argument("--query-file")
    elastic_pull.add_argument("--insecure", action="store_true")

    misp_enrich = sub.add_parser("misp-enrich", help="Enrich extracted IOCs using a live MISP instance")
    misp_enrich.add_argument("events")
    misp_enrich.add_argument("url")
    misp_enrich.add_argument("--insecure", action="store_true")
    misp_enrich.add_argument("--json", action="store_true")

    opencti_check = sub.add_parser("opencti-check", help="Validate OpenCTI GraphQL connectivity")
    opencti_check.add_argument("url")
    opencti_check.add_argument("--insecure", action="store_true")

    security_cmd = sub.add_parser("security-check", help="Evaluate local runtime security posture")
    security_cmd.add_argument("--host", default="127.0.0.1")
    security_cmd.add_argument("--command-db")
    security_cmd.add_argument("--json", action="store_true")

    benchmark_cmd = sub.add_parser("benchmark", help="Run a repeatable local investigation benchmark")
    benchmark_cmd.add_argument("--events", type=int, default=5000)
    benchmark_cmd.add_argument("--json", action="store_true")

    replay_cmd = sub.add_parser("replay", help="Replay how findings and hypotheses emerged over time")
    replay_cmd.add_argument("events")
    replay_cmd.add_argument("--json", action="store_true")

    detection_replay_cmd = sub.add_parser("detection-replay", help="Replay an incident against the current detection pack")
    detection_replay_cmd.add_argument("events")
    detection_replay_cmd.add_argument("--rules", default="detections")
    detection_replay_cmd.add_argument("--json", action="store_true")

    what_if_cmd = sub.add_parser("what-if", help="Compare current and proposed detection packs against the same incident")
    what_if_cmd.add_argument("events")
    what_if_cmd.add_argument("--current-rules", default="detections")
    what_if_cmd.add_argument("--proposed-rules", required=True)
    what_if_cmd.add_argument("--json", action="store_true")

    review_cmd = sub.add_parser("case-review", help="Evaluate investigation completeness without scoring the analyst")
    review_cmd.add_argument("events")
    review_cmd.add_argument("--checklist")
    review_cmd.add_argument("--json", action="store_true")

    learn_cmd = sub.add_parser("learn-from-case", help="Generate a detection-engineering regression package from a confirmed case")
    learn_cmd.add_argument("events")
    learn_cmd.add_argument("--rules", default="detections")
    learn_cmd.add_argument("--case-id", required=True)
    learn_cmd.add_argument("-o", "--output", required=True)

    contradiction_cmd = sub.add_parser(
        "contradictions",
        help="Review supporting, contradicting and unresolved evidence for investigation hypotheses",
    )
    contradiction_cmd.add_argument("events")
    contradiction_cmd.add_argument("--json", action="store_true")

    similar_cmd = sub.add_parser(
        "similar-cases",
        help="Find explainable historical cases with similar evidence/behavior",
    )
    similar_cmd.add_argument("events")
    similar_cmd.add_argument("--database", required=True)
    similar_cmd.add_argument("--limit", type=int, default=5)
    similar_cmd.add_argument("--exclude-case-id")
    similar_cmd.add_argument("--json", action="store_true")

    enterprise_info = sub.add_parser("enterprise-info", help="Show enterprise roles and permissions")
    enterprise_info.add_argument("--json", action="store_true")

    trusted_sign = sub.add_parser("trusted-sign", help="Sign a trusted-proxy identity for integration testing")
    trusted_sign.add_argument("--subject", required=True)
    trusted_sign.add_argument("--role", choices=sorted(ROLE_PERMISSIONS), required=True)

    audit_verify = sub.add_parser("audit-verify", help="Verify a tamper-evident enterprise audit chain")
    audit_verify.add_argument("path")
    audit_verify.add_argument("--json", action="store_true")

    backup_cmd = sub.add_parser("backup", help="Create a point-in-time backup of the local SQLite command database")
    backup_cmd.add_argument("database")
    backup_cmd.add_argument("-o", "--output", required=True)

    retention_cmd = sub.add_parser("retention", help="Preview or apply file retention to exported investigation artifacts")
    retention_cmd.add_argument("directory")
    retention_cmd.add_argument("--days", type=int, required=True)
    retention_cmd.add_argument("--apply", action="store_true")
    retention_cmd.add_argument("--json", action="store_true")

    pg_schema = sub.add_parser("postgres-schema", help="Write the PostgreSQL enterprise schema")
    pg_schema.add_argument("-o", "--output")

    pg_init = sub.add_parser("postgres-init", help="Initialize SOCMind enterprise tables in PostgreSQL")
    pg_init.add_argument("--dsn", help="PostgreSQL DSN; prefer SOCMIND_POSTGRES_DSN environment variable")

    pg_health = sub.add_parser("postgres-health", help="Check PostgreSQL enterprise readiness")
    pg_health.add_argument("--dsn", help="PostgreSQL DSN; prefer SOCMIND_POSTGRES_DSN environment variable")
    pg_health.add_argument("--json", action="store_true")

    alert_ops = sub.add_parser(
        "alert-orchestrate",
        help="Promote Wazuh/Elastic alerts into deduplicated correlated SOC cases",
    )
    alert_ops.add_argument("format", choices=["wazuh", "elastic"])
    alert_ops.add_argument("path", help="Raw Wazuh JSONL or Elastic NDJSON alerts")
    alert_ops.add_argument(
        "--evidence",
        help="Optional normalized JSONL telemetry used for evidence collection; defaults to parsed alert events",
    )
    store = alert_ops.add_mutually_exclusive_group(required=True)
    store.add_argument("--database", help="SQLite command-center database")
    store.add_argument("--postgres-dsn", help="PostgreSQL DSN; prefer SOCMIND_POSTGRES_DSN")
    alert_ops.add_argument("--evidence-dir", default="socmind-evidence")
    alert_ops.add_argument("--correlation-window", type=int, default=15)
    alert_ops.add_argument("--correlation-threshold", type=int, default=55)
    alert_ops.add_argument("--evidence-before", type=int, default=15)
    alert_ops.add_argument("--evidence-after", type=int, default=15)
    alert_ops.add_argument("--json", action="store_true")

    live_alerts = sub.add_parser(
        "alert-live",
        help="Pull live Elastic/Wazuh Indexer alerts and orchestrate them into SOC cases",
    )
    live_alerts.add_argument("provider", choices=["elastic", "wazuh-indexer"])
    live_alerts.add_argument("base_url")
    live_alerts.add_argument("index")
    live_store = live_alerts.add_mutually_exclusive_group(required=True)
    live_store.add_argument("--database", help="SQLite command-center database")
    live_store.add_argument("--postgres-dsn", help="PostgreSQL DSN; defaults to SOCMIND_POSTGRES_DSN")
    live_alerts.add_argument("--size", type=int, default=100)
    live_alerts.add_argument("--query-file")
    live_alerts.add_argument("--evidence", help="Optional normalized evidence JSONL; defaults to pulled alert events")
    live_alerts.add_argument("--evidence-dir", default="socmind-evidence")
    live_alerts.add_argument("--correlation-window", type=int, default=15)
    live_alerts.add_argument("--correlation-threshold", type=int, default=55)
    live_alerts.add_argument("--evidence-before", type=int, default=15)
    live_alerts.add_argument("--evidence-after", type=int, default=15)
    live_alerts.add_argument("--insecure", action="store_true", help="Disable TLS verification for controlled lab use only")
    live_alerts.add_argument("--json", action="store_true")

    live_evidence = sub.add_parser(
        "case-collect-evidence",
        help="Collect live Elastic/Wazuh Indexer evidence for an orchestrated case",
    )
    live_evidence.add_argument("case_id")
    live_evidence.add_argument("provider", choices=["elastic", "wazuh-indexer"])
    live_evidence.add_argument("base_url")
    live_evidence.add_argument("index")
    live_evidence.add_argument("--database", help="SQLite command-center database")
    live_evidence.add_argument("--postgres-dsn", help="PostgreSQL DSN; defaults to SOCMIND_POSTGRES_DSN")
    live_evidence.add_argument("--evidence-dir", default="socmind-evidence")
    live_evidence.add_argument("--before", type=int, default=15, help="Minutes before earliest linked alert")
    live_evidence.add_argument("--after", type=int, default=15, help="Minutes after latest linked alert")
    live_evidence.add_argument("--max-events", type=int, default=2000)
    live_evidence.add_argument("--insecure", action="store_true", help="Disable TLS verification for controlled lab use only")
    live_evidence.add_argument("--json", action="store_true")

    return parser


def _print_iocs(events, as_json: bool = False) -> None:
    iocs = extract_iocs(events)
    if as_json:
        print(json.dumps(
            [{"type": i.type, "value": i.value, "scope": i.scope} for i in iocs],
            indent=2,
        ))
        return
    if not iocs:
        print("No IOCs extracted.")
        return
    print("SOCMind IOC Summary")
    print("===================")
    for ioc in iocs:
        print(f"{ioc.type.upper():7} | {ioc.scope:12} | {ioc.value}")


def _print_hypotheses(findings) -> None:
    hypotheses = generate_hypotheses(findings)
    if not hypotheses:
        print("No investigation hypotheses generated.")
        return
    print("SOCMind Investigation Hypotheses")
    print("================================")
    for idx, item in enumerate(hypotheses, 1):
        print(f"\n[{idx}] {item.name} | confidence={item.confidence}%")
        print("Supporting:")
        for value in item.supporting:
            print(f"  + {value}")
        print("Contradicting / validation gaps:")
        for value in item.contradicting:
            print(f"  - {value}")


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "help":
        try:
            print(render_help(args.topic))
        except ValueError as exc:
            raise SystemExit(str(exc))
        return

    if args.command == "doctor":
        checks = run_doctor()
        if args.json:
            print(json.dumps(doctor_payload(), indent=2))
        else:
            print("SOCMind Doctor")
            print("==============")
            for item in checks:
                state = "OK" if item.ok else "WARN"
                print(f"[{state}] {item.name}: {item.detail}")
        raise SystemExit(0 if all(item.ok for item in checks if item.name == "python") else 1)

    if args.command == "analyze":
        events = load_jsonl(args.path)
        findings = analyze(events)
        print(render_text(findings))
        if args.timeline:
            print(); print(render_timeline(events))
        if args.iocs:
            print(); _print_iocs(events)
        if args.graph:
            print(); print(render_mermaid(events))
        if args.process_tree:
            print(); print(render_process_tree(events))
        if args.hypotheses:
            print(); _print_hypotheses(findings)
        if args.case_output:
            export_case(events, findings, args.case_output, case_id=args.case_id)
            print(f"\nCase exported -> {args.case_output}")
        return

    if args.command == "timeline":
        print(render_timeline(load_jsonl(args.path))); return

    if args.command == "iocs":
        _print_iocs(load_jsonl(args.path), as_json=args.json); return

    if args.command == "graph":
        print(render_mermaid(load_jsonl(args.path))); return

    if args.command == "case":
        events = load_jsonl(args.path)
        export_case(events, analyze(events), args.output, case_id=args.case_id)
        print(f"Case exported -> {args.output}"); return

    if args.command == "detect":
        rule = load_rule(args.rule)
        matches = evaluate_rule(rule, load_jsonl(args.events))
        print(f"{rule.id} | {rule.title}")
        print(f"matches={len(matches)} | level={rule.level} | ATT&CK={','.join(rule.attack_techniques) or '-'}")
        for event in matches:
            print(f"- {event.timestamp.isoformat()} | {event.host} | {event.event_id} | {event.process or '-'}")
        return

    if args.command in {"coverage", "gaps"}:
        events = load_jsonl(args.events)
        findings = analyze(events)
        rules = load_rules(args.rules)
        rows = build_coverage(findings, rules) if args.command == "coverage" else detection_gaps(findings, rules)
        print(render_coverage(rows)); return

    if args.command == "rule-test":
        result = run_rule_test(load_rule(args.rule), args.fixture)
        state = "PASS" if result.passed else "FAIL"
        print(f"{state} | {result.name} | expected={result.expected_matches} actual={result.actual_matches}")
        raise SystemExit(0 if result.passed else 1)

    if args.command == "tune":
        suggestions = suggest_tuning(load_dispositions(args.dispositions), min_samples=args.min_samples)
        if not suggestions:
            print("No tuning suggestions met the evidence threshold."); return
        print("SOCMind Detection Tuning Suggestions")
        print("===================================")
        for item in suggestions:
            print(f"\n{item.rule_id} | false-positive-rate={item.false_positive_rate:.0%} | samples={item.sample_size}")
            for reason in item.common_reasons:
                print(f"  - common benign context: {reason}")
            print(f"  Recommendation: {item.recommendation}")
        return

    if args.command == "enrich":
        events = load_jsonl(args.events)
        results = enrich_iocs(extract_iocs(events), [LocalIntelProvider(args.local_intel)])
        if args.json:
            print(json.dumps([{
                "type": r.type,
                "value": r.value,
                "provider": r.provider,
                "verdict": r.verdict,
                "confidence": r.confidence,
                "context": r.context,
            } for r in results], indent=2))
        else:
            if not results:
                print("No enrichment matches found.")
            for r in results:
                print(f"{r.type.upper():7} | {r.value} | {r.verdict} | confidence={r.confidence}% | {r.provider}")
        return

    if args.command == "note":
        note = append_note(
            args.journal,
            case_id=args.case_id,
            author=args.author,
            text=args.text,
            disposition=args.disposition,
        )
        print(f"Note appended -> {args.journal} | {note.case_id} | {note.author}")
        return

    if args.command == "escalate":
        events = load_jsonl(args.events)
        export_escalation_package(events, analyze(events), args.output, case_id=args.case_id)
        print(f"Escalation package exported -> {args.output}")
        return

    if args.command == "case-init":
        case = new_case(args.case_id, priority=args.priority, owner=args.owner)
        save_case(case, args.output)
        print(f"Case created -> {args.output} | {case.case_id} | {case.priority}")
        return

    if args.command == "case-assign":
        case = load_case(args.case_file)
        assign(case, args.owner)
        save_case(case, args.case_file)
        print(f"Case assigned -> {case.case_id} | {case.owner}")
        return

    if args.command == "case-transition":
        case = load_case(args.case_file)
        transition(case, args.state)
        save_case(case, args.case_file)
        print(f"Case state -> {case.case_id} | {case.state}")
        return

    if args.command == "sla":
        case = load_case(args.case_file)
        status = evaluate_sla(case.opened_at, priority=case.priority)
        print(
            f"{case.case_id} | {status.priority} | elapsed={status.elapsed_minutes}m "
            f"| target={status.target_minutes}m | breached={'yes' if status.breached else 'no'}"
        )
        return

    if args.command == "evidence":
        item = fingerprint(args.path)
        print(f"SHA256 {item.sha256} | bytes={item.size_bytes} | {item.path}")
        return

    if args.command == "evidence-verify":
        try:
            result = verify_evidence_manifest(args.path, args.manifest)
        except (OSError, ValueError, TypeError) as exc:
            raise SystemExit(f"Evidence verification failed: {exc}") from exc
        payload = verification_payload(result)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            state = "VALID" if result.valid else "INVALID"
            print(
                f"Evidence integrity {state} | sha256={result.actual_sha256} | "
                f"bytes={result.actual_size} | events={result.actual_event_count}"
            )
            if result.errors:
                for error in result.errors:
                    print(f"  - {error}")
        if not result.valid:
            raise SystemExit(1)
        return

    if args.command == "handoff":
        events = load_jsonl(args.events)
        text = render_shift_handoff(events, analyze(events), case_id=args.case_id)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"Shift handoff exported -> {args.output}")
        else:
            print(text)
        return

    if args.command == "investigate":
        target = build_workspace(
            args.events,
            args.output,
            case_id=args.case_id,
            priority=args.priority,
            owner=args.owner,
        )
        print(f"Investigation workspace -> {target}")
        return

    if args.command == "audit":
        entry = append_audit(
            args.journal,
            case_id=args.case_id,
            actor=args.actor,
            action=args.action,
            detail=args.detail,
        )
        print(f"Audit appended -> {args.journal} | {entry.case_id} | {entry.action}")
        return

    if args.command == "command-register":
        case = load_case(args.case_file)
        upsert_case(args.database, case, source=args.source, title=args.title, evidence_path=args.events)
        print(f"Command center updated -> {args.database} | {case.case_id}")
        return

    if args.command == "command-ack":
        acknowledge_case(args.database, args.case_id, actor="cli-analyst")
        print(f"Case acknowledged -> {args.case_id}")
        return

    if args.command == "command-assign":
        assign_case(args.database, args.case_id, args.owner, actor=args.actor)
        print(f"Case assigned -> {args.case_id} | {args.owner}")
        return

    if args.command == "command-transition":
        transition_case(args.database, args.case_id, args.state, actor=args.actor)
        print(f"Case state -> {args.case_id} | {args.state}")
        return

    if args.command == "command-note":
        note_id = add_case_note(
            args.database,
            args.case_id,
            author=args.author,
            text=args.text,
            disposition=args.disposition,
        )
        print(f"Case note added -> {args.case_id} | note={note_id}")
        return

    if args.command == "command-show":
        print(json.dumps(case_detail(args.database, args.case_id), indent=2))
        return

    if args.command == "command-center":
        snapshot = command_center_snapshot(args.database)
        if args.json:
            print(json.dumps(snapshot, indent=2))
        else:
            summary = snapshot["summary"]
            print("SOCMind Command Center")
            print("======================")
            print(
                f"total={summary['total']} active={summary['active']} "
                f"p1={summary['p1_active']} unassigned={summary['unassigned']} "
                f"sla-breached={summary['sla_breached']} "
                f"mtta={summary['mtta_minutes'] if summary['mtta_minutes'] is not None else '-'}m "
                f"mttr={summary['mttr_minutes'] if summary['mttr_minutes'] is not None else '-'}m"
            )
            print("\nQueue:")
            for item in snapshot["queue"]:
                sla = item["sla"]
                sla_text = "closed" if sla is None else (
                    "BREACHED" if sla["breached"] else f"{sla['remaining_minutes']}m left"
                )
                print(
                    f"- {item['priority']} | {item['case_id']} | {item['state']} | "
                    f"{item['owner'] or 'Unassigned'} | {sla_text}"
                )
        return

    if args.command == "lead-health":
        snapshot = lead_snapshot(
            args.events,
            rules_dir=args.rules,
            dispositions_path=args.dispositions,
        )
        if args.json:
            print(json.dumps(snapshot, indent=2))
        else:
            summary = snapshot["summary"]
            print("SOCMind Detection Health")
            print("========================")
            print(
                f"events={summary['events']} findings={summary['findings']} "
                f"rules={summary['rules']} coverage="
                f"{summary['coverage_percent'] if summary['coverage_percent'] is not None else '-'}% "
                f"noisy={summary['noisy_rules']}"
            )
            print("\nRule health:")
            for item in snapshot["detection_health"]:
                fp = "-" if item["false_positive_rate"] is None else f"{item['false_positive_rate']:.0%}"
                tp = "-" if item["true_positive_rate"] is None else f"{item['true_positive_rate']:.0%}"
                print(
                    f"- {item['rule_id']} | score={item['score']} | TP={tp} | FP={fp} "
                    f"| samples={item['sample_size']} | noisy={'yes' if item['noisy'] else 'no'}"
                )
        return

    if args.command == "shift-brief":
        command = command_center_snapshot(args.database)
        lead = lead_snapshot(
            args.events,
            rules_dir=args.rules,
            dispositions_path=args.dispositions,
        )
        text = render_shift_brief(command, lead)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"Shift brief exported -> {args.output}")
        else:
            print(text)
        return

    if args.command == "demo-init":
        result = create_demo(
            args.output,
            windows_events=args.windows_events,
            linux_events=args.linux_events,
        )
        print(f"Demo database -> {result['database']}")
        print(
            "Launch -> socmind web "
            f"{result['events']} --case-id {result['case_id']} "
            f"--command-db {result['database']} "
            "--rules detections --dispositions examples/dispositions.jsonl"
        )
        return

    if args.command in {"wazuh-check", "wazuh-agents"}:
        username = args.username or os.environ.get("WAZUH_API_USER")
        password = os.environ.get("WAZUH_API_PASSWORD")
        if not username or not password:
            raise SystemExit("Set WAZUH_API_USER and WAZUH_API_PASSWORD (or pass --username). Password is intentionally read from the environment.")
        client = WazuhClient(
            args.url,
            username=username,
            password=password,
            verify_tls=not args.insecure,
        )
        if args.command == "wazuh-check":
            status = integration_check("wazuh", client)
            print(f"{'OK' if status.ok else 'FAIL'} | {status.provider} | {status.detail}")
            raise SystemExit(0 if status.ok else 1)
        payload = client.agents(limit=args.limit)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            items = payload.get("data", {}).get("affected_items", [])
            print(f"Wazuh agents: {len(items)}")
            for item in items:
                print(f"- {item.get('id', '-')} | {item.get('name', '-')} | {item.get('status', '-')}")
        return

    if args.command == "elastic-pull":
        client = ElasticClient(
            args.url,
            api_key=os.environ.get("ELASTIC_API_KEY"),
            bearer_token=os.environ.get("ELASTIC_BEARER_TOKEN"),
            username=os.environ.get("ELASTIC_USERNAME"),
            password=os.environ.get("ELASTIC_PASSWORD"),
            verify_tls=not args.insecure,
        )
        query = None
        if args.query_file:
            raw = json.loads(Path(args.query_file).read_text(encoding="utf-8"))
            query = raw.get("query", raw)
        count = client.export_ndjson(args.index, args.output, query=query, size=args.size)
        print(f"Elastic export -> {args.output} | hits={count}")
        return

    if args.command == "misp-enrich":
        api_key = os.environ.get("MISP_API_KEY")
        if not api_key:
            raise SystemExit("Set MISP_API_KEY in the environment.")
        provider = MISPProvider(args.url, api_key, verify_tls=not args.insecure)
        results = enrich_iocs(extract_iocs(load_jsonl(args.events)), [provider])
        rows = [{
            "type": item.type,
            "value": item.value,
            "provider": item.provider,
            "verdict": item.verdict,
            "confidence": item.confidence,
            "context": item.context,
        } for item in results]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            if not rows:
                print("No MISP matches found.")
            for row in rows:
                print(f"{row['type'].upper():7} | {row['value']} | {row['verdict']} | {row['confidence']}% | {row['context']}")
        return

    if args.command == "opencti-check":
        token = os.environ.get("OPENCTI_TOKEN")
        if not token:
            raise SystemExit("Set OPENCTI_TOKEN in the environment.")
        client = OpenCTIClient(args.url, token, verify_tls=not args.insecure)
        data = client.graphql("query { __typename }")
        print(f"OK | opencti | graphql={data.get('__typename', 'reachable')}")
        return

    if args.command == "security-check":
        token = os.environ.get("SOCMIND_API_TOKEN")
        checks = security_report(host=args.host, api_token=token, command_db=args.command_db)
        if args.json:
            print(json.dumps(security_payload(host=args.host, api_token=token, command_db=args.command_db), indent=2))
        else:
            print("SOCMind Security Check")
            print("======================")
            for item in checks:
                print(f"[{'OK' if item.ok else 'WARN'}] {item.name}: {item.detail}")
        raise SystemExit(0 if all(item.ok for item in checks) else 1)

    if args.command == "benchmark":
        result = run_benchmark(args.events)
        if args.json:
            print(json.dumps({
                "events": result.events,
                "findings": result.findings,
                "elapsed_seconds": result.elapsed_seconds,
                "events_per_second": result.events_per_second,
            }, indent=2))
        else:
            print("SOCMind Benchmark")
            print("=================")
            print(f"events={result.events}")
            print(f"findings={result.findings}")
            print(f"elapsed={result.elapsed_seconds:.6f}s")
            print(f"throughput={result.events_per_second:.1f} events/s")
        return

    if args.command == "replay":
        events = load_jsonl(args.events)
        if args.json:
            print(json.dumps(replay_payload(events), indent=2))
        else:
            print(render_replay(events))
        return

    if args.command == "detection-replay":
        events = load_jsonl(args.events)
        rules = load_rules(args.rules)
        if args.json:
            print(json.dumps(detection_replay_payload(events, rules), indent=2))
        else:
            print(render_detection_replay(events, rules))
        return

    if args.command == "what-if":
        events = load_jsonl(args.events)
        current_rules = load_rules(args.current_rules)
        proposed_rules = load_rules(args.proposed_rules)
        if args.json:
            result = compare_rule_packs(events, current_rules, proposed_rules)
            print(json.dumps({
                "current": result.current,
                "proposed": result.proposed,
                "first_detection_step_improvement": result.first_detection_step_improvement,
                "visibility_delta": result.visibility_delta,
                "blind_step_delta": result.blind_step_delta,
                "newly_covered_techniques": result.newly_covered_techniques,
            }, indent=2))
        else:
            print(render_what_if(events, current_rules, proposed_rules))
        return

    if args.command == "case-review":
        events = load_jsonl(args.events)
        checklist = load_checklist(args.checklist)
        if args.json:
            print(json.dumps(quality_payload(events, checklist=checklist), indent=2))
        else:
            print(render_quality_review(events, checklist=checklist))
        return

    if args.command == "learn-from-case":
        events = load_jsonl(args.events)
        rules = load_rules(args.rules)
        target = generate_regression_package(
            events,
            rules,
            args.output,
            case_id=args.case_id,
        )
        print(f"Detection regression package -> {target}")
        return

    if args.command == "contradictions":
        events = load_jsonl(args.events)
        if args.json:
            print(json.dumps(contradiction_payload(events), indent=2))
        else:
            print(render_contradictions(events))
        return

    if args.command == "similar-cases":
        events = load_jsonl(args.events)
        if args.json:
            print(json.dumps(
                similarity_payload(
                    events,
                    args.database,
                    limit=args.limit,
                    exclude_case_id=args.exclude_case_id,
                ),
                indent=2,
            ))
        else:
            print(render_similarity(
                events,
                args.database,
                limit=args.limit,
                exclude_case_id=args.exclude_case_id,
            ))
        return

    if args.command == "alert-live":
        query = None
        if args.query_file:
            raw_query = json.loads(
                Path(args.query_file).read_text(encoding="utf-8")
            )
            query = raw_query.get("query", raw_query)

        if args.provider == "wazuh-indexer":
            api_key = None
            bearer_token = os.environ.get("WAZUH_INDEXER_JWT")
            username = (
                os.environ.get("WAZUH_INDEXER_USER")
                or os.environ.get("WAZUH_INDEXER_USERNAME")
            )
            password = os.environ.get("WAZUH_INDEXER_PASSWORD")
            sort_field = "timestamp"
        else:
            api_key = os.environ.get("ELASTIC_API_KEY")
            bearer_token = os.environ.get("ELASTIC_BEARER_TOKEN")
            username = (
                os.environ.get("ELASTIC_USER")
                or os.environ.get("ELASTIC_USERNAME")
            )
            password = os.environ.get("ELASTIC_PASSWORD")
            sort_field = "@timestamp"

        client = ElasticClient(
            args.base_url,
            api_key=api_key,
            bearer_token=bearer_token,
            username=username,
            password=password,
            verify_tls=not args.insecure,
        )
        response = client.search(
            args.index,
            query=query,
            size=args.size,
            sort=[{sort_field: {"order": "asc"}}],
        )
        hits = response.get("hits", {}).get("hits", [])
        alert_events = (
            wazuh_search_hits_to_events(hits)
            if args.provider == "wazuh-indexer"
            else parse_elastic_hits(hits)
        )
        evidence_events = (
            load_jsonl(args.evidence)
            if args.evidence
            else alert_events
        )
        postgres_dsn = args.postgres_dsn or os.environ.get("SOCMIND_POSTGRES_DSN")
        results = []
        for event in alert_events:
            alert = alert_from_event(event)
            if args.database:
                result = orchestrate_alert_sqlite(
                    args.database,
                    alert,
                    evidence_events,
                    evidence_dir=args.evidence_dir,
                    correlation_window_minutes=args.correlation_window,
                    correlation_threshold=args.correlation_threshold,
                    evidence_before_minutes=args.evidence_before,
                    evidence_after_minutes=args.evidence_after,
                )
            else:
                if not postgres_dsn:
                    raise SystemExit("Set SOCMIND_POSTGRES_DSN or pass --postgres-dsn.")
                result = orchestrate_alert_postgres(
                    postgres_dsn,
                    alert,
                    evidence_events,
                    evidence_dir=args.evidence_dir,
                    correlation_window_minutes=args.correlation_window,
                    correlation_threshold=args.correlation_threshold,
                    evidence_before_minutes=args.evidence_before,
                    evidence_after_minutes=args.evidence_after,
                )
            results.append({
                "alert_id": alert.alert_id,
                "title": alert.title,
                "source": alert.source,
                "case_id": result.case_id,
                "created": result.created,
                "duplicate": result.duplicate,
                "priority": result.priority,
                "correlation_score": result.correlation_score,
                "correlation_reasons": result.correlation_reasons,
                "evidence_count": result.evidence_count,
                "evidence_path": result.evidence_path,
            })

        payload = {
            "provider": args.provider,
            "hits": len(hits),
            "alerts": len(results),
            "new_cases": sum(1 for item in results if item["created"]),
            "duplicates": sum(1 for item in results if item["duplicate"]),
            "results": results,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("SOCMind Live Alert Orchestration")
            print("===============================")
            print(
                f"provider={args.provider} hits={len(hits)} "
                f"alerts={len(results)} new_cases={payload['new_cases']} "
                f"duplicates={payload['duplicates']}"
            )
            for item in results:
                state = "DUPLICATE" if item["duplicate"] else (
                    "NEW CASE" if item["created"] else "CORRELATED"
                )
                print(
                    f"{item['alert_id']} | {state} | {item['case_id']} | "
                    f"{item['priority']} | correlation={item['correlation_score']}"
                )
        return

    if args.command == "alert-orchestrate":
        if args.format == "wazuh":
            alert_events = parse_wazuh_alerts(args.path)
        else:
            alert_events = parse_elastic_ndjson(args.path)

        evidence_events = (
            load_jsonl(args.evidence)
            if args.evidence
            else alert_events
        )
        dsn = args.postgres_dsn or os.environ.get("SOCMIND_POSTGRES_DSN")
        results = []
        for event in alert_events:
            alert = alert_from_event(event)
            if args.database:
                result = orchestrate_alert_sqlite(
                    args.database,
                    alert,
                    evidence_events,
                    evidence_dir=args.evidence_dir,
                    correlation_window_minutes=args.correlation_window,
                    correlation_threshold=args.correlation_threshold,
                    evidence_before_minutes=args.evidence_before,
                    evidence_after_minutes=args.evidence_after,
                )
            else:
                if not dsn:
                    raise SystemExit(
                        "Set SOCMIND_POSTGRES_DSN or pass --postgres-dsn."
                    )
                result = orchestrate_alert_postgres(
                    dsn,
                    alert,
                    evidence_events,
                    evidence_dir=args.evidence_dir,
                    correlation_window_minutes=args.correlation_window,
                    correlation_threshold=args.correlation_threshold,
                    evidence_before_minutes=args.evidence_before,
                    evidence_after_minutes=args.evidence_after,
                )
            results.append({
                "alert_id": alert.alert_id,
                "title": alert.title,
                "source": alert.source,
                "case_id": result.case_id,
                "created": result.created,
                "duplicate": result.duplicate,
                "priority": result.priority,
                "correlation_score": result.correlation_score,
                "correlation_reasons": result.correlation_reasons,
                "evidence_count": result.evidence_count,
                "evidence_path": result.evidence_path,
            })

        if args.json:
            print(json.dumps({
                "alerts": len(results),
                "new_cases": sum(1 for item in results if item["created"]),
                "duplicates": sum(1 for item in results if item["duplicate"]),
                "results": results,
            }, indent=2))
        else:
            print("SOCMind Alert Orchestration")
            print("==========================")
            for item in results:
                state = (
                    "DUPLICATE"
                    if item["duplicate"]
                    else "NEW CASE"
                    if item["created"]
                    else "CORRELATED"
                )
                print(
                    f"{item['alert_id']} | {state} | {item['case_id']} | "
                    f"{item['priority']} | correlation={item['correlation_score']} | "
                    f"evidence={item['evidence_count']}"
                )
                for reason in item["correlation_reasons"]:
                    print(f"  - {reason['detail']}")
        return

    if args.command == "case-collect-evidence":
        if args.database and args.postgres_dsn:
            raise SystemExit("Choose one case store: --database or --postgres-dsn.")
        postgres_dsn = args.postgres_dsn
        if not args.database and not postgres_dsn:
            postgres_dsn = os.environ.get("SOCMIND_POSTGRES_DSN")
        if not args.database and not postgres_dsn:
            raise SystemExit("Pass --database or set/pass SOCMIND_POSTGRES_DSN.")

        if args.provider == "elastic":
            client = ElasticClient(
                args.base_url,
                api_key=os.environ.get("ELASTIC_API_KEY"),
                bearer_token=os.environ.get("ELASTIC_BEARER_TOKEN"),
                username=os.environ.get("ELASTIC_USER"),
                password=os.environ.get("ELASTIC_PASSWORD"),
                verify_tls=not args.insecure,
            )
        else:
            user = os.environ.get("WAZUH_INDEXER_USER")
            password = os.environ.get("WAZUH_INDEXER_PASSWORD")
            if not user or not password:
                raise SystemExit(
                    "Set WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD."
                )
            client = ElasticClient(
                args.base_url,
                username=user,
                password=password,
                verify_tls=not args.insecure,
            )

        kwargs = {
            "provider": args.provider,
            "index": args.index,
            "evidence_dir": args.evidence_dir,
            "before_minutes": args.before,
            "after_minutes": args.after,
            "max_events": args.max_events,
        }
        if args.database:
            result = collect_case_evidence_sqlite(
                args.database,
                args.case_id,
                client,
                **kwargs,
            )
        else:
            result = collect_case_evidence_postgres(
                postgres_dsn,
                args.case_id,
                client,
                **kwargs,
            )

        payload = collection_payload(result)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("SOCMind Live Evidence Collection")
            print("===============================")
            print(f"case={result.case_id}")
            print(f"provider={result.provider}")
            print(f"source={result.source_ref}")
            print(f"status={result.status}")
            print(f"window={result.window_start} -> {result.window_end}")
            print(f"fetched_events={result.fetched_events}")
            print(f"total_hits={result.total_hits if result.total_hits is not None else '-'}")
            print(f"truncated={result.truncated}")
            print(f"evidence_events={result.evidence_events}")
            print(f"evidence_path={result.evidence_path}")
            print(f"collection_id={result.collection_id}")
        return

    if args.command == "enterprise-info":
        payload = {
            role: sorted(permissions)
            for role, permissions in ROLE_PERMISSIONS.items()
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("SOCMind Enterprise Roles")
            print("========================")
            for role, permissions in payload.items():
                print(f"{role}: {', '.join(permissions)}")
        return

    if args.command == "trusted-sign":
        secret = os.environ.get("SOCMIND_TRUSTED_PROXY_SECRET")
        if not secret:
            raise SystemExit("Set SOCMIND_TRUSTED_PROXY_SECRET in the environment.")
        print(json.dumps(
            trusted_proxy_headers(secret, args.subject, args.role),
            indent=2,
        ))
        return

    if args.command == "audit-verify":
        valid, records, error = verify_chain(args.path)
        payload = {"valid": valid, "records": records, "error": error}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"SOCMind Audit Chain | {'VALID' if valid else 'INVALID'} | records={records}")
            if error:
                print(f"error={error}")
        raise SystemExit(0 if valid else 1)

    if args.command == "backup":
        target = backup_sqlite(args.database, args.output)
        print(f"Backup -> {target}")
        return

    if args.command == "retention":
        result = retention_scan(args.directory, days=args.days, apply=args.apply)
        if args.json:
            print(json.dumps({
                "scanned": result.scanned,
                "eligible": result.eligible,
                "deleted": result.deleted,
                "dry_run": result.dry_run,
            }, indent=2))
        else:
            print(render_retention(result))
        return

    if args.command == "postgres-schema":
        schema = postgres_schema()
        if args.output:
            Path(args.output).write_text(schema, encoding="utf-8")
            print(f"PostgreSQL schema -> {args.output}")
        else:
            print(schema)
        return

    if args.command == "postgres-init":
        dsn = args.dsn or os.environ.get("SOCMIND_POSTGRES_DSN")
        if not dsn:
            raise SystemExit("Set SOCMIND_POSTGRES_DSN or pass --dsn.")
        initialize_postgres(dsn)
        print("PostgreSQL enterprise schema initialized.")
        return

    if args.command == "postgres-health":
        dsn = args.dsn or os.environ.get("SOCMIND_POSTGRES_DSN")
        if not dsn:
            raise SystemExit("Set SOCMIND_POSTGRES_DSN or pass --dsn.")
        result = postgres_health(dsn)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("SOCMind PostgreSQL Health")
            print("=========================")
            print(f"database={result['database']}")
            print(f"user={result['user']}")
            print(f"socmind_tables={result['socmind_tables']}")
            print(f"ready={result['ready']}")
        raise SystemExit(0 if result["ready"] else 1)

    if args.command == "web":
        try:
            import uvicorn
        except ImportError as exc:
            raise RuntimeError("Web dashboard requires: pip install 'socmind[web]'") from exc
        from .webapp import create_app
        api_token = args.api_token or os.environ.get("SOCMIND_API_TOKEN")
        trusted_proxy_secret = os.environ.get("SOCMIND_TRUSTED_PROXY_SECRET")
        auth_configured = (
            args.auth_mode == "trusted-proxy" and bool(trusted_proxy_secret)
        )
        try:
            validate_web_binding(
                args.host,
                api_token=api_token,
                auth_configured=auth_configured,
                allow_unsafe_remote=args.allow_unsafe_remote,
            )
        except ValueError as exc:
            raise SystemExit(str(exc))
        postgres_dsn = args.postgres_dsn or os.environ.get("SOCMIND_POSTGRES_DSN")
        app = create_app(
            args.events,
            case_id=args.case_id,
            command_db=args.command_db,
            postgres_dsn=postgres_dsn,
            rules_dir=args.rules,
            dispositions_path=args.dispositions,
            api_token=api_token,
            proposed_rules_dir=args.proposed_rules,
            quality_checklist_path=args.quality_checklist,
            auth_mode=args.auth_mode,
            api_token_role=args.api_token_role,
            trusted_proxy_secret=trusted_proxy_secret,
            enterprise_audit_path=args.enterprise_audit,
        )
        print(f"SOCMind Web -> http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
        return

    if args.command == "ingest":
        if args.format == "linux-auth":
            events = parse_auth_log(args.path, host=args.host, year=args.year)
        elif args.format == "journald":
            events = parse_journald_json(args.path)
        elif args.format == "auditd":
            events = parse_auditd(args.path, host=args.host)
        elif args.format == "windows-evtx":
            events = parse_evtx(args.path)
        elif args.format == "wazuh":
            events = parse_wazuh_alerts(args.path)
        elif args.format == "elastic":
            events = parse_elastic_ndjson(args.path)
        else:
            events = parse_windows_event_xml(args.path)
        _events_to_jsonl(events, args.output)
        print(f"Normalized {len(events)} event(s) -> {args.output}")
