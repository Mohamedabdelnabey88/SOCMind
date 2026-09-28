import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from socmind.case_workflow import new_case
from socmind.enterprise_auth import sign_trusted_proxy_identity
from socmind.enterprise_command_center import (
    add_case_note_pg,
    assign_case_pg,
    case_detail_pg,
    command_center_snapshot_pg,
    transition_case_pg,
    upsert_case_pg,
)
from socmind.postgres_store import initialize_postgres, postgres_health, _psycopg
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
            cur.execute("TRUNCATE TABLE case_audit, case_notes, cases RESTART IDENTITY CASCADE")
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
    assert health["socmind_tables"] == 3


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
        return {
            "X-SOCMind-User": subject,
            "X-SOCMind-Role": role,
            "X-SOCMind-Signature": sign_trusted_proxy_identity(
                secret,
                subject,
                role,
            ),
        }

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
