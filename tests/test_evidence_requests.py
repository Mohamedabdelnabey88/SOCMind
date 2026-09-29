import pytest
from socmind.case_workflow import new_case
from socmind.command_center import upsert_case, case_detail
from socmind.evidence_requests import create_requirement, update_requirement, list_requirements
from socmind.rbac import Principal

ANALYST = Principal('alice', 'analyst', 'test')
LEAD = Principal('lead', 'lead', 'test')


def test_request_lifecycle_idempotency_and_permissions(tmp_path):
    db = tmp_path / 'test.db'
    upsert_case(db, new_case('C'))
    r = create_requirement(db, 'C', 'MFA result', origin='validation-gap', principal=ANALYST)
    assert create_requirement(db, 'C', 'MFA result', origin='validation-gap', principal=ANALYST) == r
    assert len(case_detail(db, 'C')['audit']) == 1
    with pytest.raises(PermissionError):
        update_requirement(db, 'C', r['requirement_id'], 'waived', reason='Not needed', principal=ANALYST)
    with pytest.raises(ValueError):
        update_requirement(db, 'C', r['requirement_id'], 'received', reason='Received', principal=ANALYST)
    update_requirement(db, 'C', r['requirement_id'], 'requested', reason='Asked IdP team', principal=ANALYST)
    with pytest.raises(ValueError):
        update_requirement(db, 'C', r['requirement_id'], 'unavailable', expected_state='required', reason='Stale', principal=ANALYST)
    update_requirement(db, 'C', r['requirement_id'], 'unavailable', reason='Retention expired', principal=ANALYST)
    assert list_requirements(db, 'C')[0]['state'] == 'unavailable'
    update_requirement(db, 'C', r['requirement_id'], 'waived', reason='Lead accepted limitation', principal=LEAD)
    assert len(case_detail(db, 'C')['audit']) == 4


def test_unknown_case_and_cross_case_updates_rejected(tmp_path):
    db = tmp_path / 'test.db'
    upsert_case(db, new_case('C'))
    upsert_case(db, new_case('D'))
    r = create_requirement(db, 'C', 'VPN logs', origin='analyst', principal=ANALYST)
    with pytest.raises(ValueError):
        create_requirement(db, 'missing', 'VPN logs', origin='analyst', principal=ANALYST)
    with pytest.raises(ValueError):
        update_requirement(db, 'D', r['requirement_id'], 'requested', reason='Request', principal=ANALYST)
    assert list_requirements(db, 'D') == []
