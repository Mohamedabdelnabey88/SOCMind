from pathlib import Path

from socmind.coverage import build_coverage, detection_gaps
from socmind.detections import load_rules
from socmind.models import Finding


ROOT = Path(__file__).resolve().parents[1]


def finding(*techniques):
    return Finding("test", "high", 80, ["reason"], list(techniques), [])


def test_coverage_identifies_covered_and_uncovered_observed_techniques():
    rules = load_rules(ROOT / "detections")
    findings = [
        finding("T1059.001 PowerShell"),
        finding("T1053.005 Scheduled Task/Job"),
        finding("T1110 Brute Force"),
    ]
    rows = build_coverage(findings, rules)
    indexed = {row.technique: row for row in rows}
    assert indexed["T1059.001"].covered
    assert indexed["T1053.005"].covered
    assert not indexed["T1110"].covered
    gaps = detection_gaps(findings, rules)
    assert [row.technique for row in gaps] == ["T1110"]
