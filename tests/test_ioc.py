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
    ip = next(ioc for ioc in iocs if ioc.type == "ip")
    assert ip.scope == "documentation"


def test_does_not_treat_user_or_process_names_as_domains():
    event = Event(
        timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
        source="test",
        event_id="1",
        host="host-1",
        user="m.abdelnaby",
        process="powershell.exe",
        parent_process="winword.exe",
    )
    iocs = extract_iocs([event])
    domains = {ioc.value for ioc in iocs if ioc.type == "domain"}
    assert "m.abdelnaby" not in domains
    assert "powershell.exe" not in domains
    assert "winword.exe" not in domains
