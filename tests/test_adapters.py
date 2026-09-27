from pathlib import Path

from socmind.adapters import parse_auth_log, parse_journald_json, parse_windows_event_xml


FIXTURES = Path(__file__).parent / "fixtures"


def test_linux_auth_parser_extracts_ssh_and_sudo():
    events = parse_auth_log(FIXTURES / "auth.log", host="linux-01", year=2026)
    assert len(events) == 7
    assert sum(e.event_id == "ssh_auth_failed" for e in events) == 5
    assert any(e.event_id == "ssh_auth_success" for e in events)
    sudo = next(e for e in events if e.event_id == "sudo_command")
    assert "useradd" in (sudo.command_line or "")


def test_journald_parser_extracts_events():
    events = parse_journald_json(FIXTURES / "journald.jsonl")
    assert len(events) == 2
    assert events[0].host == "linux-01"
    assert events[0].event_id == "ssh_auth_failed"
    assert events[1].event_id == "ssh_auth_success"


def test_windows_xml_parser_extracts_security_fields():
    events = parse_windows_event_xml(FIXTURES / "windows-events.xml")
    assert len(events) == 2
    assert events[0].event_id == "4625"
    assert events[0].user == "analyst"
    assert events[0].src_ip == "198.51.100.22"
    assert events[0].host == "WS-023"
