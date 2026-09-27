import json
from datetime import datetime, timezone

from socmind.case import export_case
from socmind.models import Event, Finding


def test_case_export_contains_graph_hypotheses_and_playbook(tmp_path):
    event = Event(
        datetime(2026, 9, 28, tzinfo=timezone.utc),
        "windows",
        "4624",
        "WS-01",
        user="analyst",
        src_ip="198.51.100.20",
    )
    finding = Finding(
        "Repeated failed logons followed by successful authentication",
        "high",
        80,
        ["test"],
        ["T1110"],
        [event],
    )
    output = tmp_path / "case.json"
    export_case([event], [finding], output, case_id="CASE-001")
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["case_id"] == "CASE-001"
    assert payload["summary"]["findings"] == 1
    assert payload["graph"]["nodes"]
    assert payload["hypotheses"]
    assert payload["findings"][0]["playbook"]
