import argparse

from .engine import analyze
from .io import load_jsonl
from .report import render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socmind",
        description="Cross-platform SOC Tier 1/2 investigation toolkit",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    analyze_cmd = sub.add_parser("analyze", help="Analyze normalized JSONL security events")
    analyze_cmd.add_argument("path", help="Path to JSONL event file")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "analyze":
        print(render_text(analyze(load_jsonl(args.path))))
