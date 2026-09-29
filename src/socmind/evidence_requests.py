"""Analyst-controlled requirements; unavailable evidence is never a contradiction."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json

from .command_center import connect
from .enterprise_command_center import _connect
from .rbac import Principal, require_permission

STATES = {
    'required': {'requested', 'received', 'unavailable', 'waived'},
    'requested': {'received', 'unavailable', 'waived'},
    'received': {'required'},
    'unavailable': {'requested', 'received', 'waived'},
    'waived': {'required'},
}
SCHEMA = '''CREATE TABLE IF NOT EXISTS evidence_requirements (
    requirement_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    label TEXT NOT NULL,
    origin TEXT NOT NULL,
    state TEXT NOT NULL,
    evidence_reference TEXT,
    updated_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requirements_case ON evidence_requirements(case_id, state);
'''


@contextmanager
def transaction(target, *, postgres=False):
    """Initialize through normal stores, then lock a case before mutations."""
    conn = _connect(target) if postgres else connect(target)
    try:
        with conn:
            if postgres:
                cur = conn.cursor()
            else:
                conn.execute('BEGIN IMMEDIATE')
                cur = conn.cursor()
            def execute(sql, values=()):
                cur.execute(sql.replace('?', '%s') if postgres else sql, values)
                return cur
            yield execute
    finally:
        conn.close()


def _text(value, label, limit=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f'{label} must be nonempty text of at most {limit} characters')
    return value.strip()


def _case(execute, case_id, postgres):
    row = execute('SELECT case_id FROM cases WHERE case_id=?' + (' FOR UPDATE' if postgres else ''), (case_id,)).fetchone()
    if row is None:
        raise ValueError(f'Unknown case: {case_id}')


def _audit(execute, case_id, actor, action, payload, now):
    execute('INSERT INTO case_audit(case_id,actor,action,detail,timestamp) VALUES(?,?,?,?,?)',
            (case_id, actor, action, json.dumps(payload, sort_keys=True), now))


def create_requirement(target, case_id, label, *, origin, principal: Principal, postgres=False):
    require_permission(principal, 'case.note')
    label, origin = _text(label, 'Label'), _text(origin, 'Origin')
    identifier = hashlib.sha256(json.dumps([case_id, origin, label], ensure_ascii=False).encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with transaction(target, postgres=postgres) as execute:
        _case(execute, case_id, postgres)
        row = execute('SELECT * FROM evidence_requirements WHERE requirement_id=?', (identifier,)).fetchone()
        if row:
            return dict(row)
        execute('INSERT INTO evidence_requirements VALUES(?,?,?,?,?,?,?,?,?)',
                (identifier, case_id, label, origin, 'required', None, now, principal.subject, 'Validation gap'))
        _audit(execute, case_id, principal.subject, 'evidence-required', {'id': identifier, 'label': label, 'origin': origin}, now)
        return dict(execute('SELECT * FROM evidence_requirements WHERE requirement_id=?', (identifier,)).fetchone())


def update_requirement(target, case_id, requirement_id, state, *, reason, principal: Principal,
                       evidence_reference=None, expected_state=None, postgres=False):
    require_permission(principal, 'case.note')
    if state == 'waived':
        require_permission(principal, 'case.transition')
    reason = _text(reason, 'Reason')
    if state == 'received':
        evidence_reference = _text(evidence_reference, 'Evidence reference')
    now = datetime.now(timezone.utc).isoformat()
    with transaction(target, postgres=postgres) as execute:
        _case(execute, case_id, postgres)
        row = execute('SELECT * FROM evidence_requirements WHERE requirement_id=? AND case_id=?', (requirement_id, case_id)).fetchone()
        if row is None:
            raise ValueError('Unknown evidence requirement')
        row = dict(row)
        if expected_state is not None and row['state'] != expected_state:
            raise ValueError('Evidence requirement changed; refresh before retrying')
        if state not in STATES.get(row['state'], set()):
            raise ValueError(f"Invalid requirement transition: {row['state']} -> {state}")
        execute('UPDATE evidence_requirements SET state=?,evidence_reference=?,updated_at=?,actor=?,reason=? WHERE requirement_id=?',
                (state, evidence_reference, now, principal.subject, reason, requirement_id))
        _audit(execute, case_id, principal.subject, 'evidence-requirement-transition',
               {'id': requirement_id, 'from': row['state'], 'to': state, 'reason': reason, 'evidence_reference': evidence_reference}, now)
        return dict(execute('SELECT * FROM evidence_requirements WHERE requirement_id=?', (requirement_id,)).fetchone())


def list_requirements(target, case_id, *, postgres=False):
    with transaction(target, postgres=postgres) as execute:
        _case(execute, case_id, postgres)
        return [dict(row) for row in execute('SELECT * FROM evidence_requirements WHERE case_id=? ORDER BY requirement_id', (case_id,)).fetchall()]


def requirements_from_quality(target, case_id, review, *, principal, postgres=False):
    return [create_requirement(target, case_id, item.label, origin=f'quality:{item.key}',
                               principal=principal, postgres=postgres)
            for item in review.items if item.applicable and not item.complete]
