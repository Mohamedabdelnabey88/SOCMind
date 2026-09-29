from contextlib import contextmanager
import json
from .command_center import connect
from .enterprise_command_center import _connect

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

