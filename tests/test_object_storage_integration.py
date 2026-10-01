"""Real HTTPS MinIO contract test; never disables certificate verification."""
from concurrent.futures import ThreadPoolExecutor
import os
import uuid
import pytest

from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.evidence_artifacts import register_artifact, verify_artifacts
from socmind.evidence_storage import configured_store
from socmind.rbac import Principal

pytestmark = pytest.mark.skipif(not os.getenv('SOCMIND_TEST_S3_ENDPOINT'), reason='HTTPS test object store not configured')


def test_real_minio_immutable_registration_and_tamper_detection(tmp_path):
    import boto3
    endpoint=os.environ['SOCMIND_TEST_S3_ENDPOINT']
    assert endpoint.startswith('https://')
    client=boto3.client('s3',endpoint_url=endpoint)
    bucket='socmind-ci-'+uuid.uuid4().hex
    client.create_bucket(Bucket=bucket)
    store=configured_store(bucket=bucket,endpoint=endpoint)
    db=tmp_path/'cases.db'
    upsert_case(db,new_case('OBJECT-CASE'))
    source=tmp_path/'evidence.jsonl'
    source.write_bytes(b'{"original":true}\n')
    actor=Principal('test-collector','analyst','test')
    def register(_):
        return register_artifact(db,'OBJECT-CASE',source,store,storage_id='minio',source='fixture',principal=actor)
    with ThreadPoolExecutor(max_workers=4) as pool:
        artifacts=list(pool.map(register,range(8)))
    assert len({a['artifact_id'] for a in artifacts}) == 1
    assert verify_artifacts(db,'OBJECT-CASE',{'minio':store},principal=actor)[0]['integrity_status']=='verified'
    # Explicit adversarial mutation in the isolated test bucket.
    key='socmind-evidence/'+artifacts[0]['storage_key']
    client.put_object(Bucket=bucket,Key=key,Body=b'tampered fixture')
    assert verify_artifacts(db,'OBJECT-CASE',{'minio':store},principal=actor)[0]['integrity_status']=='mismatch'
    with pytest.raises(ValueError):
        register(0)
    client.delete_object(Bucket=bucket,Key=key)
    assert verify_artifacts(db,'OBJECT-CASE',{'minio':store},principal=actor)[0]['integrity_status']=='missing'
