import argparse
import json
from pathlib import Path

from .adapters import (
    parse_auditd,
    parse_auth_log,
    parse_evtx,
    parse_journald_json,
    parse_windows_event_xml,
)
from .case import export_case
from .coverage import build_coverage, detection_gaps, render_coverage
from .detections import evaluate_rule, load_rule, load_rules
from .engine import analyze
from .graph import render_mermaid
from .hypothesis import generate_hypotheses
from .io import load_jsonl
from .ioc import extract_iocs
from .process_tree import render_process_tree
from .report import render_text
from .rule_tests import run_rule_test
from .timeline import render_timeline
from .tuning import load_dispositions, suggest_tuning


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
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = sub.add_parser("analyze", help="Analyze normalized JSONL security events")
    analyze_cmd.add_argument("path", help="Path to JSONL event file")
    analyze_cmd.add_argument("--timeline", action="store_true")
    analyze_cmd.add_argument("--iocs", action="store_true")
    analyze_cmd.add_argument("--graph", action="store_true")
    analyze_cmd.add_argument("--process-tree", action="store_true")
    analyze_cmd.add_argument("--hypotheses", action="store_true")
    analyze_cmd.add_argument("--case-output")
    analyze_cmd.add_argument("--case-id", default="SOCMIND-CASE")

    ingest = sub.add_parser("ingest", help="Normalize raw Windows/Linux telemetry")
    ingest.add_argument(
        "format",
        choices=["linux-auth", "journald", "auditd", "windows-xml", "windows-evtx"],
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
        print(render_timeline(load_jsonl(args.path)))
        return

    if args.command == "iocs":
        _print_iocs(load_jsonl(args.path), as_json=args.json)
        return

    if args.command == "graph":
        print(render_mermaid(load_jsonl(args.path)))
        return

    if args.command == "case":
        events = load_jsonl(args.path)
        findings = analyze(events)
        export_case(events, findings, args.output, case_id=args.case_id)
        print(f"Case exported -> {args.output}")
        return

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
        rows = (
            build_coverage(findings, rules)
            if args.command == "coverage"
            else detection_gaps(findings, rules)
        )
        print(render_coverage(rows))
        return

    if args.command == "rule-test":
        result = run_rule_test(load_rule(args.rule), args.fixture)
        state = "PASS" if result.passed else "FAIL"
        print(
            f"{state} | {result.name} | expected={result.expected_matches} "
            f"actual={result.actual_matches}"
        )
        raise SystemExit(0 if result.passed else 1)

    if args.command == "tune":
        suggestions = suggest_tuning(
            load_dispositions(args.dispositions),
            min_samples=args.min_samples,
        )
        if not suggestions:
            print("No tuning suggestions met the evidence threshold.")
            return
        print("SOCMind Detection Tuning Suggestions")
        print("===================================")
        for item in suggestions:
            print(
                f"\n{item.rule_id} | false-positive-rate={item.false_positive_rate:.0%} "
                f"| samples={item.sample_size}"
            )
            for reason in item.common_reasons:
                print(f"  - common benign context: {reason}")
            print(f"  Recommendation: {item.recommendation}")
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
        else:
            events = parse_windows_event_xml(args.path)
        _events_to_jsonl(events, args.output)
        print(f"Normalized {len(events)} event(s) -> {args.output}")
