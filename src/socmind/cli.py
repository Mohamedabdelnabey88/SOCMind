import argparse
import json
from pathlib import Path

from .adapters import parse_auth_log, parse_journald_json, parse_windows_event_xml
from .engine import analyze
from .io import load_jsonl
from .report import render_text
from .timeline import render_timeline


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
    analyze_cmd.add_argument("--timeline", action="store_true", help="Print evidence timeline")

    ingest = sub.add_parser("ingest", help="Normalize raw Windows/Linux telemetry into JSONL")
    ingest.add_argument("format", choices=["linux-auth", "journald", "windows-xml"])
    ingest.add_argument("path", help="Input telemetry file")
    ingest.add_argument("-o", "--output", required=True, help="Normalized JSONL output")
    ingest.add_argument("--host", default="linux-host", help="Host name for auth.log sources")
    ingest.add_argument("--year", type=int, help="Year for traditional syslog timestamps")

    timeline_cmd = sub.add_parser("timeline", help="Render a normalized evidence timeline")
    timeline_cmd.add_argument("path", help="Path to normalized JSONL event file")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "analyze":
        events = load_jsonl(args.path)
        print(render_text(analyze(events)))
        if args.timeline:
            print()
            print(render_timeline(events))
        return

    if args.command == "timeline":
        print(render_timeline(load_jsonl(args.path)))
        return

    if args.command == "ingest":
        if args.format == "linux-auth":
            events = parse_auth_log(args.path, host=args.host, year=args.year)
        elif args.format == "journald":
            events = parse_journald_json(args.path)
        else:
            events = parse_windows_event_xml(args.path)
        _events_to_jsonl(events, args.output)
        print(f"Normalized {len(events)} event(s) -> {args.output}")
