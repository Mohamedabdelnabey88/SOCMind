from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.command_center import case_detail, transition_case, upsert_case
from socmind.webapp import _case_timeline, create_app

ROOT = Path(__file__).resolve().parents[1]


def test_waiting_monitoring_and_audit(tmp_path):
    db = tmp_path / 'cases.db'
    upsert_case(db, new_case('LIFE'))
    for target, reason in [('triage', 'Initial review'), ('waiting-for-evidence', 'VPN logs requested'),
                           ('investigating', 'VPN logs received'), ('contained', 'Host isolated'),
                           ('monitoring', 'Observe for recurrence'), ('resolved', 'No recurrence')]:
        transition_case(db, 'LIFE', target, actor='lead', reason=reason)
    detail = case_detail(db, 'LIFE')
    assert detail['case']['state'] == 'resolved'
    assert detail['allowed_transitions'] == []
    assert len(detail['audit']) == 6
    assert all(row['actor'] == 'lead' and 'Reason:' in row['detail'] for row in detail['audit'])
    with pytest.raises(ValueError):
        transition_case(db, 'LIFE', 'investigating', reason='Reopen')


def test_missing_reason_rolls_back(tmp_path):
    db = tmp_path / 'cases.db'
    upsert_case(db, new_case('LIFE'))
    transition_case(db, 'LIFE', 'triage')
    for reason in [None, '', ' ', 'x' * 2001, 1]:
        with pytest.raises(ValueError):
            transition_case(db, 'LIFE', 'waiting-for-user', reason=reason)
    detail = case_detail(db, 'LIFE')
    assert detail['case']['state'] == 'triage'
    assert len(detail['audit']) == 1


def test_competing_transitions_have_one_winner(tmp_path):
    db = tmp_path / 'cases.db'
    upsert_case(db, new_case('LIFE'))
    transition_case(db, 'LIFE', 'triage')
    def attempt(target):
        try:
            transition_case(db, 'LIFE', target, reason='Reviewed')
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ['resolved', 'false-positive']))
    assert sum(results) == 1
    assert len(case_detail(db, 'LIFE')['audit']) == 2


def test_web_exposes_allowed_moves_and_persists_reason(tmp_path):
    db = tmp_path / 'cases.db'
    upsert_case(db, new_case('LIFE'))
    client = TestClient(create_app(ROOT / 'examples/attack_chain.jsonl', command_db=db))
    assert client.get('/api/cases/LIFE').json()['allowed_transitions'] == ['triage']
    assert client.post('/api/cases/LIFE/transition', json={'state': 'triage', 'reason': 'Review'}).status_code == 200
    assert client.post('/api/cases/LIFE/transition', json={'state': 'waiting-for-user'}).status_code == 400
    assert client.post('/api/cases/LIFE/transition', json={'state': 'waiting-for-user', 'reason': 'Contact owner'}).status_code == 200
    assert 'Contact owner' in client.get('/api/cases/LIFE').json()['audit'][0]['detail']


def test_timeline_sorts_instants_instead_of_wall_clock():
    detail = {'notes': [{'created_at': '2026-01-01T09:00:00+03:00', 'author': 'a', 'text': 'first'},
                        {'created_at': '2026-01-01T07:00:00Z', 'author': 'b', 'text': 'second'}]}
    entries = _case_timeline(detail, None)
    assert [entry['detail'] for entry in entries] == ['first', 'second']
    assert all({'timestamp', 'type', 'actor', 'source', 'detail'} <= entry.keys() for entry in entries)
