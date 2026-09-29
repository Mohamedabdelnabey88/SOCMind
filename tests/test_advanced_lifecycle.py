from concurrent.futures import ThreadPoolExecutor
from socmind.case_workflow import new_case
from socmind.command_center import upsert_case, transition_case, case_detail

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
