import io
from pathlib import Path
import pytest
from socmind.case_workflow import new_case
from socmind.command_center import upsert_case, case_detail
from socmind.evidence_artifacts import register_artifact, verify_artifacts
from socmind.evidence_storage import LocalEvidenceStore, S3EvidenceStore, digest
from socmind.rbac import Principal

ACTOR = Principal('alice', 'analyst', 'test')


def test_original_preserved_and_stored_tamper_detected(tmp_path):
    db = tmp_path / 'test.db'
    upsert_case(db, new_case('C'))
    original = tmp_path / 'evidence.jsonl'
    original.write_bytes(b'original evidence')
    store = LocalEvidenceStore(tmp_path / 'objects')
    item = register_artifact(db, 'C', original, store, storage_id='local', source='IdP', principal=ACTOR)
    assert original.read_bytes() == b'original evidence'
    assert register_artifact(db, 'C', original, store, storage_id='local', source='IdP', principal=ACTOR) == item
    assert len(case_detail(db, 'C')['audit']) == 1
    results = verify_artifacts(db, 'C', {'local': store}, principal=ACTOR)
    assert results[0]['integrity_status'] == 'verified'
    (store.root / item['storage_key']).write_bytes(b'tampered')
    assert verify_artifacts(db, 'C', {'local': store}, principal=ACTOR)[0]['integrity_status'] == 'mismatch'
    with pytest.raises(ValueError):
        register_artifact(db, 'C', original, store, storage_id='local', source='IdP', principal=ACTOR)
    (store.root / item['storage_key']).unlink()
    assert verify_artifacts(db, 'C', {'local': store}, principal=ACTOR)[0]['integrity_status'] == 'missing'


def test_storage_rejects_path_escape_and_symlink(tmp_path):
    store = LocalEvidenceStore(tmp_path / 'objects')
    with pytest.raises(ValueError):
        store.get('../secret')
    original = tmp_path / 'real'
    original.write_bytes(b'content')
    link = store.root / digest(b'content')
    try:
        link.symlink_to(original)
    except OSError:
        pytest.skip('Symlink creation unavailable')
    with pytest.raises(ValueError):
        store.put(digest(b'content'), b'content')
    with pytest.raises(ValueError):
        store.get(digest(b'content'))


def test_s3_adapter_conditional_write_and_close():
    class PreconditionFailed(Exception):
        response = {'Error': {'Code': 'PreconditionFailed'}}
    class FakeS3:
        def __init__(self):
            self.data = {}
        def put_object(self, **kw):
            assert kw['IfNoneMatch'] == '*'
            if kw['Key'] in self.data:
                raise PreconditionFailed()
            self.data[kw['Key']] = kw['Body']
        def get_object(self, **kw):
            return {'Body': io.BytesIO(self.data[kw['Key']])}
    client = FakeS3()
    store = S3EvidenceStore(client, 'evidence')
    sha = digest(b'evidence')
    store.put(sha, b'evidence')
    store.put(sha, b'evidence')
    assert store.get(sha) == b'evidence'
    client.data['socmind-evidence/' + sha] = b'tampered'
    with pytest.raises(ValueError):
        store.put(sha, b'evidence')
