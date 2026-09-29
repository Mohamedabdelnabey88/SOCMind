from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from socmind.rule_lifecycle import (
    load_rule_registry,
    record_coverage_delta,
    record_false_positive_observation,
    record_incident_replay,
    register_rule,
    rule_lifecycle_detail,
    test_registered_rule as run_registered_rule_test,
    transition_rule,
    update_rule_version,
    validate_registered_rule_syntax,
)


ROOT = Path(__file__).resolve().parents[1]
RULE = ROOT / "detections/windows/suspicious-powershell.yml"
FIXTURE = ROOT / "tests/fixtures/powershell-rule-test.json"
EVENTS = ROOT / "tests/fixtures/rule-events.jsonl"
RULE_ID = "socmind-win-powershell-hidden"


def _register(registry):
    return register_rule(
        registry,
        RULE,
        owner="detection-team",
        actor="tier2@example.com",
        role="senior-analyst",
        version="1.0.0",
        note="Initial governed registration",
    )


def _record_all_gates(registry):
    syntax = validate_registered_rule_syntax(
        registry,
        RULE_ID,
        actor="tier2@example.com",
        role="senior-analyst",
    )
    assert syntax["status"] == "passed"

    test = run_registered_rule_test(
        registry,
        RULE_ID,
        FIXTURE,
        actor="tier2@example.com",
        role="senior-analyst",
    )
    assert test["status"] == "passed"

    replay = record_incident_replay(
        registry,
        RULE_ID,
        EVENTS,
        actor="tier2@example.com",
        role="senior-analyst",
        case_id="CONFIRMED-001",
    )
    assert replay["events"] == 2

    fp = record_false_positive_observation(
        registry,
        RULE_ID,
        actor="tier2@example.com",
        role="senior-analyst",
        sample_size=20,
        false_positives=1,
        note="Validated against representative admin activity",
    )
    assert fp["false_positive_rate"] == 0.05

    coverage = record_coverage_delta(
        registry,
        RULE_ID,
        actor="tier2@example.com",
        role="senior-analyst",
        visibility_delta=12.5,
        newly_covered_techniques=["T1059.001"],
        note="Closed confirmed PowerShell visibility gap",
    )
    assert coverage["visibility_delta"] == 12.5


def test_rule_registration_preserves_governance_metadata(tmp_path):
    registry = tmp_path / "rule-registry.json"
    record = _register(registry)

    assert record["rule_id"] == RULE_ID
    assert record["status"] == "experimental"
    assert record["version"] == "1.0.0"
    assert record["owner"] == "detection-team"
    assert record["attack_mapping"] == ["T1059.001"]
    assert record["syntax_status"]["status"] == "passed"
    assert record["test_status"]["status"] == "not-run"
    assert record["history"][0]["action"] == "registered"

    persisted = load_rule_registry(registry)
    assert persisted["schema_version"] == 1
    assert RULE_ID in persisted["rules"]


def test_analyst_cannot_register_or_manage_rule_lifecycle(tmp_path):
    registry = tmp_path / "rule-registry.json"

    with pytest.raises(PermissionError):
        register_rule(
            registry,
            RULE,
            owner="detection-team",
            actor="tier1@example.com",
            role="analyst",
        )


def test_approval_requires_lead_and_all_validation_gates(tmp_path):
    registry = tmp_path / "rule-registry.json"
    _register(registry)

    testing = transition_rule(
        registry,
        RULE_ID,
        "testing",
        actor="tier2@example.com",
        role="senior-analyst",
        note="Start controlled validation",
    )
    assert testing["status"] == "testing"

    with pytest.raises(PermissionError):
        transition_rule(
            registry,
            RULE_ID,
            "approved",
            actor="tier2@example.com",
            role="senior-analyst",
            note="Attempt approval without lead authority",
        )

    with pytest.raises(ValueError, match="Rule cannot be promoted"):
        transition_rule(
            registry,
            RULE_ID,
            "approved",
            actor="lead@example.com",
            role="lead",
            note="Premature approval attempt",
        )

    _record_all_gates(registry)

    still_testing = rule_lifecycle_detail(registry, RULE_ID)
    assert still_testing["status"] == "testing"

    approved = transition_rule(
        registry,
        RULE_ID,
        "approved",
        actor="lead@example.com",
        role="lead",
        note="Validation evidence reviewed and accepted",
    )
    assert approved["status"] == "approved"

    production = transition_rule(
        registry,
        RULE_ID,
        "production",
        actor="lead@example.com",
        role="lead",
        note="Lead-authorized production promotion",
    )
    assert production["status"] == "production"
    assert production["history"][-1]["from_status"] == "approved"
    assert production["history"][-1]["to_status"] == "production"


def test_production_deprecation_and_retirement_require_lead_authority(tmp_path):
    registry = tmp_path / "rule-registry.json"
    _register(registry)
    transition_rule(
        registry,
        RULE_ID,
        "testing",
        actor="tier2@example.com",
        role="senior-analyst",
        note="Begin validation",
    )
    _record_all_gates(registry)
    transition_rule(
        registry,
        RULE_ID,
        "approved",
        actor="lead@example.com",
        role="lead",
        note="Validation approved",
    )
    transition_rule(
        registry,
        RULE_ID,
        "production",
        actor="lead@example.com",
        role="lead",
        note="Production promotion",
    )

    with pytest.raises(PermissionError):
        transition_rule(
            registry,
            RULE_ID,
            "deprecated",
            actor="tier2@example.com",
            role="senior-analyst",
            note="T2 must not deprecate production rule",
        )

    deprecated = transition_rule(
        registry,
        RULE_ID,
        "deprecated",
        actor="lead@example.com",
        role="lead",
        note="Superseded by tuned detection",
    )
    assert deprecated["status"] == "deprecated"

    with pytest.raises(PermissionError):
        transition_rule(
            registry,
            RULE_ID,
            "retired",
            actor="tier2@example.com",
            role="senior-analyst",
            note="T2 must not retire rule",
        )

    retired = transition_rule(
        registry,
        RULE_ID,
        "retired",
        actor="lead@example.com",
        role="lead",
        note="Retired after replacement validation",
    )
    assert retired["status"] == "retired"


def test_version_change_requires_semver_and_change_note(tmp_path):
    registry = tmp_path / "rule-registry.json"
    _register(registry)

    with pytest.raises(ValueError, match="semantic version"):
        update_rule_version(
            registry,
            RULE_ID,
            version="v2",
            actor="tier2@example.com",
            role="senior-analyst",
            note="Invalid version",
        )

    updated = update_rule_version(
        registry,
        RULE_ID,
        version="1.1.0",
        actor="tier2@example.com",
        role="senior-analyst",
        note="Improve command-line scope",
    )
    assert updated["version"] == "1.1.0"
    assert updated["change_notes"][-1]["note"] == "Improve command-line scope"
    assert updated["syntax_status"]["status"] == "not-run"
    assert updated["syntax_status"]["version"] == "1.1.0"
    assert updated["test_status"]["status"] == "not-run"
    assert updated["test_status"]["version"] == "1.1.0"


def test_rule_content_change_invalidates_previous_approval_evidence(tmp_path):
    registry = tmp_path / "rule-registry.json"
    mutable_rule = tmp_path / "mutable-rule.yml"
    mutable_rule.write_text(RULE.read_text(encoding="utf-8"), encoding="utf-8")

    register_rule(
        registry,
        mutable_rule,
        owner="detection-team",
        actor="tier2@example.com",
        role="senior-analyst",
        version="1.0.0",
    )
    transition_rule(
        registry,
        RULE_ID,
        "testing",
        actor="tier2@example.com",
        role="senior-analyst",
        note="Begin validation",
    )

    validate_registered_rule_syntax(
        registry,
        RULE_ID,
        actor="tier2@example.com",
        role="senior-analyst",
    )
    run_registered_rule_test(
        registry,
        RULE_ID,
        FIXTURE,
        actor="tier2@example.com",
        role="senior-analyst",
    )
    record_incident_replay(
        registry,
        RULE_ID,
        EVENTS,
        actor="tier2@example.com",
        role="senior-analyst",
        case_id="CONFIRMED-002",
    )
    record_false_positive_observation(
        registry,
        RULE_ID,
        actor="tier2@example.com",
        role="senior-analyst",
        sample_size=10,
        false_positives=0,
        note="No false positives in validation sample",
    )
    record_coverage_delta(
        registry,
        RULE_ID,
        actor="tier2@example.com",
        role="senior-analyst",
        visibility_delta=10.0,
        newly_covered_techniques=["T1059.001"],
    )

    mutable_rule.write_text(
        mutable_rule.read_text(encoding="utf-8") + "\n# changed after validation\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="current rule content"):
        transition_rule(
            registry,
            RULE_ID,
            "approved",
            actor="lead@example.com",
            role="lead",
            note="Should fail because content changed after validation",
        )


def test_concurrent_false_positive_updates_do_not_lose_history(tmp_path):
    registry = tmp_path / "rule-registry.json"
    _register(registry)

    def record(index):
        return record_false_positive_observation(
            registry,
            RULE_ID,
            actor=f"tier2-{index}@example.com",
            role="senior-analyst",
            sample_size=10,
            false_positives=index % 2,
            note=f"Concurrent validation sample {index}",
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(record, range(8)))

    detail = rule_lifecycle_detail(registry, RULE_ID)
    assert len(detail["false_positive_history"]) == 8
    notes = {item["note"] for item in detail["false_positive_history"]}
    assert len(notes) == 8


def test_registry_rejects_symlink_target_when_supported(tmp_path):
    target = tmp_path / "real-registry.json"
    target.write_text('{"schema_version":1,"rules":{}}', encoding="utf-8")
    link = tmp_path / "registry-link.json"

    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform")

    with pytest.raises(ValueError, match="must not be a symlink"):
        load_rule_registry(link)
