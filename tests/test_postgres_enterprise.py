import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.enterprise_auth import trusted_proxy_headers
from socmind.enterprise_command_center import (
    add_case_note_pg,
    assign_case_pg,
    case_detail_pg,
    command_center_snapshot_pg,
    record_case_activity_pg,
    transition_case_pg,
    upsert_case_pg,
)
from socmind.postgres_store import initialize_postgres, postgres_health, _psycopg
from socmind.evidence_requests import (
    create_requirement_pg,
    ensure_suggested_requirements_pg,
    list_requirements_pg,
    update_requirement_pg,
)
from socmind.orchestration import orchestrate_alert_postgres
from socmind.production_ops import AlertRecord
from socmind.io import load_jsonl
from socmind.live_evidence import collect_case_evidence_postgres
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]
DSN = os.environ.get("SOCMIND_TEST_POSTGRES_DSN")


pytestmark = pytest.mark.skipif(
    not DSN,
    reason="SOCMIND_TEST_POSTGRES_DSN not configured",
)


def reset_database():
    psycopg = _psycopg()
    initialize_postgres(DSN)
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE evidence_requirements, evidence_collections, case_alerts, alerts, case_audit, case_notes, cases RESTART IDENTITY CASCADE")
        conn.commit()


def test_postgres_enterprise_store_round_trip():
    reset_database()
    upsert_case_pg(
        DSN,
        new_case("PG-001", priority="P1"),
        source="wazuh",
        title="PostgreSQL enterprise case",
        evidence_path=str(ROOT / "examples/attack_chain.jsonl"),
    )
    assign_case_pg(DSN, "PG-001", "tier2", actor="lead")
    transition_case_pg(DSN, "PG-001", "triage", actor="tier2")
    note_id = add_case_note_pg(
        DSN,
        "PG-001",
        author="tier2",
        text="Validated enterprise case evidence",
    )
    assert note_id >= 1

    detail = case_detail_pg(DSN, "PG-001")
    assert detail["case"]["owner"] == "tier2"
    assert detail["case"]["state"] == "triage"
    assert detail["notes"]
    assert detail["audit"]

    snap = command_center_snapshot_pg(DSN)
    assert snap["summary"]["total"] == 1
    assert snap["summary"]["p1_active"] == 1

    health = postgres_health(DSN)
    assert health["ready"]
    assert health["socmind_tables"] == 7


def test_postgres_lifecycle_pause_resume_and_schema_migration():
    reset_database()
    upsert_case_pg(
        DSN,
        new_case("PG-LIFECYCLE", priority="P1"),
        source="elastic",
        title="Lifecycle pause case",
    )
    transition_case_pg(DSN, "PG-LIFECYCLE", "triage", actor="tier1")
    transition_case_pg(
        DSN,
        "PG-LIFECYCLE",
        "waiting-for-evidence",
        actor="tier1",
    )

    psycopg = _psycopg()
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT sla_paused_at,sla_paused_seconds
                FROM cases WHERE case_id=%s
                """,
                ("PG-LIFECYCLE",),
            )
            paused_at, paused_seconds = cur.fetchone()
            assert paused_at is not None
            assert int(paused_seconds) == 0
            cur.execute(
                """
                UPDATE cases
                SET sla_paused_at=NOW() - INTERVAL '10 minutes'
                WHERE case_id=%s
                """,
                ("PG-LIFECYCLE",),
            )
        conn.commit()

    snap = command_center_snapshot_pg(DSN)
    item = next(x for x in snap["queue"] if x["case_id"] == "PG-LIFECYCLE")
    assert item["sla"]["paused"] is True

    transition_case_pg(DSN, "PG-LIFECYCLE", "investigating", actor="tier1")
    detail = case_detail_pg(DSN, "PG-LIFECYCLE")
    assert detail["case"]["sla_paused_at"] is None
    assert detail["case"]["sla_paused_seconds"] >= 9 * 60

    snap = command_center_snapshot_pg(DSN)
    item = next(x for x in snap["queue"] if x["case_id"] == "PG-LIFECYCLE")
    assert item["sla"]["paused"] is False
    assert item["sla"]["paused_minutes"] >= 9


def test_postgres_evidence_requirements_round_trip_and_idempotency():
    reset_database()
    upsert_case_pg(
        DSN,
        new_case("PG-REQ-001", priority="P2"),
        source="elastic",
        title="PostgreSQL evidence requirements",
        evidence_path=str(ROOT / "examples/attack_chain.jsonl"),
    )
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")

    first = ensure_suggested_requirements_pg(
        DSN,
        case_id="PG-REQ-001",
        events=events,
        requested_by="tier1",
    )
    second = ensure_suggested_requirements_pg(
        DSN,
        case_id="PG-REQ-001",
        events=events,
        requested_by="tier1",
    )
    assert first == second
    assert first

    requirement_id = first[0]
    update_requirement_pg(
        DSN,
        requirement_id,
        status="requested",
        actor="tier1",
        assigned_to="identity-team",
    )
    update_requirement_pg(
        DSN,
        requirement_id,
        status="received",
        actor="tier2",
        response_summary="Identity evidence collected",
        evidence_reference="case://PG-REQ-001/idp/context",
    )

    rows = list_requirements_pg(DSN, "PG-REQ-001")
    received = next(
        row for row in rows
        if row["requirement_id"] == requirement_id
    )
    assert received["status"] == "received"
    assert received["received_at"] is not None

    detail = case_detail_pg(DSN, "PG-REQ-001")
    assert detail["evidence_requirements"]
    snap = command_center_snapshot_pg(DSN)
    item = next(x for x in snap["queue"] if x["case_id"] == "PG-REQ-001")
    assert item["evidence_requirements"]["open"] == len(first) - 1


def test_postgres_concurrent_requirement_creation_collapses_to_one_row():
    reset_database()
    upsert_case_pg(
        DSN,
        new_case("PG-REQ-CONCURRENT", priority="P2"),
        source="wazuh",
        title="Concurrent requirement",
    )

    def create():
        return create_requirement_pg(
            DSN,
            case_id="PG-REQ-CONCURRENT",
            key="vpn-history",
            title="Collect VPN history",
            source="network",
            target="alice",
            rationale="VPN context missing",
            requested_by="tier1",
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(lambda _: create(), range(4)))

    assert len(set(ids)) == 1
    assert len(list_requirements_pg(DSN, "PG-REQ-CONCURRENT")) == 1


def test_postgres_case_activities_are_persistent_and_auditable():
    reset_database()
    upsert_case_pg(
        DSN,
        new_case("PG-TIMELINE-ACT", priority="P2"),
        source="elastic",
        title="PostgreSQL timeline activities",
    )
    record_case_activity_pg(
        DSN,
        "PG-TIMELINE-ACT",
        activity="escalation",
        actor="tier2",
        detail="Escalated to IR for privileged account impact",
    )
    record_case_activity_pg(
        DSN,
        "PG-TIMELINE-ACT",
        activity="detection-feedback",
        actor="lead",
        detail="Add regression coverage for observed chain",
    )

    detail = case_detail_pg(DSN, "PG-TIMELINE-ACT")
    actions = {row["action"] for row in detail["audit"]}
    assert "escalated" in actions
    assert "detection-feedback-recorded" in actions


def test_postgres_web_workspace_with_trusted_proxy_rbac(tmp_path):
    reset_database()
    upsert_case_pg(
        DSN,
        new_case("PG-WEB-001", priority="P1"),
        source="elastic",
        title="Enterprise web case",
        evidence_path=str(ROOT / "examples/attack_chain.jsonl"),
    )

    secret = "proxy-test-secret"
    audit = tmp_path / "enterprise-audit.jsonl"
    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        postgres_dsn=DSN,
        rules_dir=ROOT / "detections",
        auth_mode="trusted-proxy",
        trusted_proxy_secret=secret,
        enterprise_audit_path=audit,
    )
    client = TestClient(app)

    def headers(subject, role):
        return trusted_proxy_headers(secret, subject, role)

    viewer = headers("viewer@example.com", "viewer")
    lead = headers("lead@example.com", "lead")

    assert client.get("/api/me", headers=viewer).status_code == 200
    assert client.get("/api/command-center", headers=viewer).status_code == 200
    assert client.post(
        "/api/cases/PG-WEB-001/assign",
        headers=viewer,
        json={"owner": "tier2"},
    ).status_code == 403

    assigned = client.post(
        "/api/cases/PG-WEB-001/assign",
        headers=lead,
        json={"owner": "tier2"},
    )
    assert assigned.status_code == 200
    assert assigned.json()["case"]["owner"] == "tier2"

    note = client.post(
        "/api/cases/PG-WEB-001/notes",
        headers=lead,
        json={"text": "Enterprise audit test"},
    )
    assert note.status_code == 200

    health = client.get("/health").json()
    assert health["case_store"] == "postgres"
    assert health["enterprise_audit"] is True

    audit_status = client.get(
        "/api/enterprise/audit/verify",
        headers=lead,
    )
    assert audit_status.status_code == 200
    assert audit_status.json()["valid"] is True
    assert audit_status.json()["records"] >= 2


def test_postgres_alert_orchestration_correlates_and_deduplicates(tmp_path):
    reset_database()
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    base = events[0]
    evidence_dir = tmp_path / "evidence"

    first = AlertRecord(
        "PG-ALERT-001",
        "elastic",
        base.timestamp,
        "Initial suspicious authentication",
        8,
        base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="ELASTIC-AUTH-1",
    )
    first_result = orchestrate_alert_postgres(
        DSN,
        first,
        events,
        evidence_dir=evidence_dir,
    )
    assert first_result.created is True

    second = AlertRecord(
        "PG-ALERT-002",
        "elastic",
        base.timestamp + timedelta(minutes=2),
        "Follow-up suspicious authentication",
        13,
        base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="ELASTIC-AUTH-2",
    )
    second_result = orchestrate_alert_postgres(
        DSN,
        second,
        events,
        evidence_dir=evidence_dir,
    )
    assert second_result.created is False
    assert second_result.case_id == first_result.case_id
    assert second_result.correlation_score >= 55

    detail = case_detail_pg(DSN, first_result.case_id)
    assert detail["case"]["priority"] == "P1"
    assert len(detail["alerts"]) == 2
    assert detail["alerts"][1]["correlation_reasons"]

    duplicate = orchestrate_alert_postgres(
        DSN,
        second,
        events,
        evidence_dir=evidence_dir,
    )
    assert duplicate.duplicate is True
    assert duplicate.case_id == first_result.case_id


def test_concurrent_postgres_alerts_collapse_into_one_case(tmp_path):
    reset_database()
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    base = events[0]
    evidence_dir = tmp_path / "evidence"
    alerts = [
        AlertRecord(
            f"PG-CONCURRENT-{idx}",
            "elastic",
            base.timestamp + timedelta(seconds=idx),
            f"Concurrent enterprise alert {idx}",
            10,
            base.host,
            user=base.user,
            src_ip=base.src_ip,
            rule_id=f"PG-RULE-{idx}",
        )
        for idx in (1, 2)
    ]

    def run(alert):
        return orchestrate_alert_postgres(
            DSN,
            alert,
            events,
            evidence_dir=evidence_dir,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, alerts))

    assert len({item.case_id for item in results}) == 1
    assert sum(1 for item in results if item.created) == 1
    detail = case_detail_pg(DSN, results[0].case_id)
    assert len(detail["alerts"]) == 2


def test_postgres_live_evidence_collection_journal(tmp_path):
    reset_database()
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    base = events[0]
    evidence_dir = tmp_path / "evidence"

    alert = AlertRecord(
        "PG-LIVE-001",
        "elastic",
        base.timestamp,
        "PostgreSQL live evidence",
        12,
        base.host,
        user=base.user,
        src_ip=base.src_ip,
        rule_id="PG-LIVE-RULE",
    )
    orchestrated = orchestrate_alert_postgres(
        DSN,
        alert,
        events,
        evidence_dir=tmp_path / "initial",
    )

    class FakeElastic:
        def search(self, index, *, query=None, size=100, sort=None):
            return {
                "hits": {
                    "hits": [{
                        "_id": "pg-live-hit-1",
                        "_index": "logs-*",
                        "_source": {
                            "@timestamp": base.timestamp.isoformat(),
                            "event": {"code": base.event_id},
                            "host": {"name": base.host},
                            "user": {"name": base.user},
                            "source": {"ip": base.src_ip},
                        },
                    }]
                }
            }

    result = collect_case_evidence_postgres(
        DSN,
        orchestrated.case_id,
        FakeElastic(),
        provider="elastic",
        index="logs-*",
        evidence_dir=evidence_dir,
    )
    assert result.status == "completed"
    assert result.fetched_events == 1

    detail = case_detail_pg(DSN, orchestrated.case_id)
    assert detail["evidence_collections"]
    assert detail["evidence_collections"][0]["status"] == "completed"
    assert detail["evidence_collections"][0]["event_count"] == 1
    assert detail["evidence_collections"][0]["query"]["bool"]


def test_postgres_immutable_artifact_metadata(tmp_path):
    from socmind.evidence_artifacts import register_artifact, verify_artifacts
    from socmind.evidence_storage import LocalEvidenceStore
    from socmind.rbac import Principal
    reset_database()
    upsert_case_pg(DSN, new_case('PG-ARTIFACT'))
    path = tmp_path / 'original.bin'
    path.write_bytes(b'original')
    store = LocalEvidenceStore(tmp_path / 'objects')
    actor = Principal('collector', 'analyst', 'test')
    item = register_artifact(DSN, 'PG-ARTIFACT', path, store, storage_id='local', source='test', principal=actor, postgres=True)
    assert verify_artifacts(DSN, 'PG-ARTIFACT', {'local': store}, principal=actor, postgres=True)[0]['integrity_status'] == 'verified'
    (store.root / item['storage_key']).write_bytes(b'changed')
    assert verify_artifacts(DSN, 'PG-ARTIFACT', {'local': store}, principal=actor, postgres=True)[0]['integrity_status'] == 'mismatch'


def test_postgres_alert_identity_is_namespaced_by_source(tmp_path):
    from datetime import datetime, timezone
    reset_database()
    now=datetime.now(timezone.utc)
    a=AlertRecord('provider-shared-id','wazuh',now,'First',8,'host-a',user='a')
    b=AlertRecord('provider-shared-id','elastic',now,'Second',8,'host-b',user='b')
    first=orchestrate_alert_postgres(DSN,a,[],evidence_dir=tmp_path/'evidence')
    second=orchestrate_alert_postgres(DSN,b,[],evidence_dir=tmp_path/'evidence')
    assert first.created and second.created and first.case_id != second.case_id
    assert case_detail_pg(DSN,second.case_id)['alerts'][0]['alert_id']=='provider-shared-id'
    assert orchestrate_alert_postgres(DSN,b,[],evidence_dir=tmp_path/'evidence').duplicate
