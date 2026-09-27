from pathlib import Path

from socmind.dashboard import build_dashboard_payload
from socmind.io import load_jsonl


ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_payload_contains_soc_views():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    payload = build_dashboard_payload(events, case_id="WEB-001")
    assert payload["case_id"] == "WEB-001"
    assert payload["summary"]["events"] == len(events)
    assert payload["findings"]
    assert payload["graph"]["nodes"]
    assert payload["timeline"]
    assert payload["techniques"]
