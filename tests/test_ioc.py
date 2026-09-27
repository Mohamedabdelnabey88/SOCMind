from datetime import datetime, timezone

from socmind.ioc import extract_iocs
from socmind.models import Event


def test_extracts_ip_domain_url_and_hash():
    event = Event(
        timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
        source="test",
        event_id="1",
        host="host-1",
        src_ip="198.51.100.22",
        command_line=(
            "curl https://updates.example.org/a.exe "
            "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
    )
    iocs = extract_iocs([event])
    values = {(ioc.type, ioc.value) for ioc in iocs}
    assert ("ip", "198.51.100.22") in values
    assert ("domain", "updates.example.org") in values
    assert ("url", "https://updates.example.org/a.exe") in values
    assert ("sha256", "a" * 64) in values
