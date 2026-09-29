"""Artifact metadata is immutable; verification is an audited observation."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat

from .evidence_requests import transaction, _case, _audit, _text
from .evidence_storage import EvidenceStore, MAX_ARTIFACT_BYTES, digest
from .rbac import Principal, require_permission

SCHEMA = '''CREATE TABLE IF NOT EXISTS evidence_artifacts (
    artifact_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    original_name TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    collector TEXT NOT NULL,
    source TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    storage_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON evidence_artifacts(case_id);
'''


def register_artifact(target, case_id, path, store: EvidenceStore, *, storage_id, source,
                      principal: Principal, postgres=False):
    require_permission(principal, 'case.note')
    source, storage_id = _text(source, 'Source'), _text(storage_id, 'Storage identifier')
    path = Path(path).absolute()
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError('Symlink artifacts are not permitted')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Artifact must be a regular file')
        data = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError('Artifact exceeds 64 MiB limit')
    sha = digest(data)
    artifact_id = hashlib.sha256(json.dumps([case_id, sha, path.name, source, storage_id]).encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with transaction(target, postgres=postgres) as execute:
        _case(execute, case_id, postgres)
        existing = execute('SELECT * FROM evidence_artifacts WHERE artifact_id=?', (artifact_id,)).fetchone()
        if existing:
            if digest(store.get(sha)) != sha:
                raise ValueError('Registered evidence has been modified')
            return dict(existing)
        # An interrupted DB commit can leave an unreferenced blob, never deleted silently.
        store.put(sha, data)
        execute('INSERT INTO evidence_artifacts VALUES(?,?,?,?,?,?,?,?,?,?)',
                (artifact_id, case_id, sha, len(data), path.name, now, principal.subject, source, sha, storage_id))
        _audit(execute, case_id, principal.subject, 'evidence-registered',
               {'artifact_id': artifact_id, 'sha256': sha, 'size_bytes': len(data), 'source': source}, now)
        return dict(execute('SELECT * FROM evidence_artifacts WHERE artifact_id=?', (artifact_id,)).fetchone())


def verify_artifacts(target, case_id, stores: dict[str, EvidenceStore], *, principal, postgres=False):
    require_permission(principal, 'case.read')
    now = datetime.now(timezone.utc).isoformat()
    results = []
    with transaction(target, postgres=postgres) as execute:
        _case(execute, case_id, postgres)
        rows = execute('SELECT * FROM evidence_artifacts WHERE case_id=? ORDER BY artifact_id', (case_id,)).fetchall()
        for row in rows:
            item = dict(row)
            try:
                data = stores[item['storage_id']].get(item['storage_key'])
                status = 'verified' if len(data) == item['size_bytes'] and digest(data) == item['sha256'] else 'mismatch'
            except FileNotFoundError:
                status = 'missing'
            except (OSError, ValueError, KeyError):
                status = 'unavailable'
            results.append({**item, 'integrity_status': status, 'verified_at': now})
        _audit(execute, case_id, principal.subject, 'evidence-verified',
               [{'artifact_id': item['artifact_id'], 'status': item['integrity_status']} for item in results], now)
    return results
