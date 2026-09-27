from pathlib import Path

from socmind.adapters.auditd import parse_auditd


def test_auditd_parser(tmp_path: Path):
    sample = (
        'type=EXECVE msg=audit(1790591000.123:88): '
        'argc=2 a0="sudo" a1="id" acct="ops" exe="/usr/bin/sudo"\n'
    )
    path = tmp_path / "audit.log"
    path.write_text(sample, encoding="utf-8")
    events = parse_auditd(path, host="linux-01")
    assert len(events) == 1
    assert events[0].source == "auditd"
    assert events[0].host == "linux-01"
    assert events[0].user == "ops"
