import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from socmind.audit_chain import append_record, verify_chain
from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.enterprise_auth import (
    AuthConfig,
    authenticate,
    trusted_proxy_headers,
)
from socmind.enterprise_ops import (
    backup_sqlite,
    postgres_schema,
    retention_scan,
)
from socmind.rbac import Principal, require_permission
from socmind.webapp import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_rbac_permissions_are_enforced():
    analyst = Principal("alice", "analyst", "test")
    require_permission(analyst, "case.note")
    with pytest.raises(PermissionError):
        require_permission(analyst, "case.assign")


def test_trusted_proxy_signature_authentication():
    secret = "integration-secret"
    headers = trusted_proxy_headers(secret, "alice@example.com", "lead")
    principal = authenticate(
        {key.lower(): value for key, value in headers.items()},
        AuthConfig(mode="trusted-proxy", trusted_proxy_secret=secret),
    )
    assert principal.subject == "alice@example.com"
    assert principal.role == "lead"


def test_trusted_proxy_rejects_stale_replay():
    secret = "integration-secret"
    headers = trusted_proxy_headers(
        secret,
        "alice@example.com",
        "lead",
        timestamp=1,
    )
    with pytest.raises(PermissionError, match="expired"):
        authenticate(
            {key.lower(): value for key, value in headers.items()},
            AuthConfig(mode="trusted-proxy", trusted_proxy_secret=secret),
        )


def test_tamper_evident_audit_detects_modified_record(tmp_path):
    audit = tmp_path / "audit.jsonl"
    append_record(audit, case_id="INC-1", actor="alice", action="note", detail="one")
    append_record(audit, case_id="INC-1", actor="alice", action="assign", detail="two")
    assert verify_chain(audit) == (True, 2, None)

    rows = audit.read_text(encoding="utf-8").splitlines()
    item = json.loads(rows[0])
    item["detail"] = "tampered"
    rows[0] = json.dumps(item)
    audit.write_text("\n".join(rows) + "\n", encoding="utf-8")

    valid, record, error = verify_chain(audit)
    assert valid is False
    assert record == 1
    assert error == "entry-hash mismatch"


def test_backup_and_retention_are_safe_by_default(tmp_path):
    db = tmp_path / "soc.db"
    upsert_case(db, new_case("INC-1"))
    backup = backup_sqlite(db, tmp_path / "backup" / "soc.db")
    assert backup.exists()

    old = tmp_path / "exports" / "old.json"
    old.parent.mkdir()
    old.write_text("{}", encoding="utf-8")
    os.utime(old, (1, 1))

    preview = retention_scan(tmp_path / "exports", days=30)
    assert preview.dry_run
    assert preview.eligible == 1
    assert old.exists()

    applied = retention_scan(tmp_path / "exports", days=30, apply=True)
    assert applied.deleted == 1
    assert not old.exists()

    with pytest.raises(ValueError):
        backup_sqlite(db, db)

    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = tmp_path / "exports" / "outside-link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        return
    os.utime(outside, (1, 1))
    preview = retention_scan(tmp_path / "exports", days=30)
    assert preview.eligible == 0
    assert outside.exists()


def test_postgres_schema_contains_enterprise_tables_and_indexes():
    schema = postgres_schema()
    assert "CREATE TABLE IF NOT EXISTS cases" in schema
    assert "CREATE TABLE IF NOT EXISTS case_quality" in schema
    assert "REFERENCES cases(case_id)" in schema
    assert "idx_cases_priority_state" in schema


def test_web_rbac_and_enterprise_audit(tmp_path):
    db = tmp_path / "soc.db"
    audit = tmp_path / "enterprise-audit.jsonl"
    upsert_case(
        db,
        new_case("INC-001", priority="P1"),
        evidence_path=ROOT / "examples/attack_chain.jsonl",
    )

    app = create_app(
        ROOT / "examples/attack_chain.jsonl",
        command_db=db,
        api_token="secret",
        api_token_role="analyst",
        enterprise_audit_path=audit,
    )
    client = TestClient(app)

    headers = {"X-SOCMind-Token": "secret"}
    assert client.get("/api/me", headers=headers).json()["role"] == "analyst"
    assert client.post("/api/cases/INC-001/acknowledge", headers=headers).status_code == 200
    assert client.post(
        "/api/cases/INC-001/notes",
        headers=headers,
        json={"text": "Validated evidence"},
    ).status_code == 200
    assert client.post(
        "/api/cases/INC-001/assign",
        headers=headers,
        json={"owner": "tier2"},
    ).status_code == 403

    valid, records, error = verify_chain(audit)
    assert valid
    assert records == 2
    assert error is None
