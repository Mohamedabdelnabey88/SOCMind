from pathlib import Path

from socmind.engine import analyze
from socmind.handoff import render_shift_handoff
from socmind.io import load_jsonl
from socmind.provenance import fingerprint


ROOT = Path(__file__).resolve().parents[1]


def test_evidence_fingerprint_is_stable():
    path = ROOT / "examples/attack_chain.jsonl"
    a = fingerprint(path)
    b = fingerprint(path)
    assert a.sha256 == b.sha256
    assert a.size_bytes > 0


def test_shift_handoff_contains_next_actions():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    text = render_shift_handoff(events, analyze(events), case_id="INC-001")
    assert "SOC Shift Handoff" in text
    assert "Next analyst actions" in text
