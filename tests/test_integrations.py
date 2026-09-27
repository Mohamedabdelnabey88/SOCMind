from pathlib import Path

from socmind.adapters import parse_elastic_ndjson, parse_wazuh_alerts
from socmind.enrichment import LocalIntelProvider, enrich_iocs
from socmind.ioc import IOC
from socmind.notes import append_note, load_notes


ROOT = Path(__file__).resolve().parents[1]


def test_wazuh_adapter():
    events = parse_wazuh_alerts(ROOT / "tests/fixtures/wazuh-alerts.jsonl")
    assert len(events) == 1
    assert events[0].source == "wazuh"
    assert events[0].event_id == "4625"
    assert events[0].user == "analyst"


def test_elastic_adapter():
    events = parse_elastic_ndjson(ROOT / "tests/fixtures/elastic-events.ndjson")
    assert len(events) == 1
    assert events[0].source == "elastic-ecs"
    assert events[0].process.lower().endswith("powershell.exe")
    assert events[0].dst_ip == "203.0.113.77"


def test_local_enrichment_provider():
    provider = LocalIntelProvider(ROOT / "examples/local-intel.json")
    results = enrich_iocs([IOC("ip", "203.0.113.77", "documentation")], [provider])
    assert len(results) == 1
    assert results[0].verdict == "suspicious-demo"


def test_analyst_notes_round_trip(tmp_path):
    path = tmp_path / "notes.jsonl"
    append_note(
        path,
        case_id="INC-001",
        author="analyst1",
        text="Validated source host.",
        disposition="needs-review",
    )
    notes = load_notes(path)
    assert len(notes) == 1
    assert notes[0].case_id == "INC-001"
