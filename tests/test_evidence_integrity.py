import json

from socmind.evidence_integrity import (
    evidence_manifest_path,
    verify_evidence_manifest,
    write_evidence_manifest,
)


def _write_evidence(path):
    path.write_text(
        '{"timestamp":"2026-09-29T00:00:00+00:00","source":"wazuh"}\n'
        '{"timestamp":"2026-09-29T00:01:00+00:00","source":"wazuh"}\n',
        encoding="utf-8",
    )


def test_manifest_records_required_integrity_metadata(tmp_path):
    evidence = tmp_path / "CASE-1.jsonl"
    _write_evidence(evidence)

    manifest = write_evidence_manifest(
        evidence,
        case_id="CASE-1",
        source="wazuh",
        event_count=2,
        collected_at="2026-09-29T00:02:00+00:00",
    )
    payload = json.loads(manifest.read_text(encoding="utf-8"))

    assert manifest == evidence_manifest_path(evidence)
    assert payload["manifest_version"] == 1
    assert payload["case_id"] == "CASE-1"
    assert payload["file_name"] == "CASE-1.jsonl"
    assert payload["source"] == "wazuh"
    assert payload["event_count"] == 2
    assert payload["size_bytes"] == evidence.stat().st_size
    assert len(payload["sha256"]) == 64


def test_verify_manifest_passes_for_unchanged_evidence(tmp_path):
    evidence = tmp_path / "CASE-2.jsonl"
    _write_evidence(evidence)
    write_evidence_manifest(evidence, case_id="CASE-2", source="elastic", event_count=2)

    result = verify_evidence_manifest(evidence)

    assert result.valid is True
    assert result.errors == ()
    assert result.actual_sha256 == result.expected_sha256
    assert result.actual_event_count == 2


def test_verify_manifest_detects_evidence_tampering(tmp_path):
    evidence = tmp_path / "CASE-3.jsonl"
    _write_evidence(evidence)
    write_evidence_manifest(evidence, case_id="CASE-3", source="wazuh", event_count=2)

    evidence.write_text(evidence.read_text(encoding="utf-8") + '{"tampered":true}\n', encoding="utf-8")
    result = verify_evidence_manifest(evidence)

    assert result.valid is False
    assert "sha256 mismatch" in result.errors
    assert "size mismatch" in result.errors
    assert "event_count mismatch" in result.errors


def test_merge_refuses_to_rebaseline_tampered_evidence(tmp_path):
    import pytest
    from socmind.orchestration import _merge_evidence
    from socmind.io import load_jsonl
    from pathlib import Path
    events = load_jsonl(Path(__file__).resolve().parents[1] / 'examples/attack_chain.jsonl')
    path = tmp_path / 'case.jsonl'
    _merge_evidence(path, events, case_id='C', source='test')
    manifest = evidence_manifest_path(path).read_bytes()
    path.write_bytes(path.read_bytes() + b'\n')
    with pytest.raises(ValueError, match='integrity'):
        _merge_evidence(path, events, case_id='C', source='test')
    assert evidence_manifest_path(path).read_bytes() == manifest
