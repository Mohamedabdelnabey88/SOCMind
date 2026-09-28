from pathlib import Path

from socmind.case_workflow import new_case
from socmind.command_center import upsert_case
from socmind.contradiction import contradiction_payload
from socmind.io import load_jsonl
from socmind.similarity import find_similar_cases, fingerprint_case


ROOT = Path(__file__).resolve().parents[1]


def test_contradiction_engine_surfaces_explicit_benign_context():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    events[5].data = {
        **events[5].data,
        "mfa_result": "success",
        "device_trust": "trusted",
    }

    payload = contradiction_payload(events)
    statements = [
        item["statement"]
        for hypothesis in payload["hypotheses"]
        for item in hypothesis["contradicting"]
    ]
    assert any("trusted/managed device" in value for value in statements)
    assert payload["summary"]["unresolved_questions"] > 0
    context = [
        item
        for hypothesis in payload["hypotheses"]
        for item in hypothesis["contradicting"]
        if "trusted/managed device" in item["statement"]
    ]
    assert context
    assert context[0]["timestamp"]
    assert context[0]["event_id"]
    assert context[0]["host"]


def test_case_fingerprint_is_deterministic():
    events = load_jsonl(ROOT / "examples/attack_chain.jsonl")
    first = fingerprint_case(events)
    second = fingerprint_case(events)
    assert first == second
    assert first.techniques
    assert first.event_ids


def test_similar_cases_rank_behaviorally_similar_case_first(tmp_path):
    db = tmp_path / "soc.db"
    windows = ROOT / "examples/attack_chain.jsonl"
    linux = ROOT / "examples/linux_attack_chain.jsonl"

    upsert_case(
        db,
        new_case("WIN-OLD", priority="P2"),
        source="wazuh",
        title="Historical Windows compromise chain",
        evidence_path=windows,
    )
    upsert_case(
        db,
        new_case("LINUX-OLD", priority="P2"),
        source="elastic",
        title="Historical Linux SSH investigation",
        evidence_path=linux,
    )

    current = load_jsonl(windows)
    matches = find_similar_cases(current, db, limit=5)
    assert matches
    assert matches[0].case_id == "WIN-OLD"
    assert matches[0].score > 70
    assert matches[0].shared_techniques
    assert matches[0].confidence == "high"
    assert matches[0].matched_dimensions >= 3
    assert matches[0].comparable_dimensions >= matches[0].matched_dimensions


def test_similarity_does_not_claim_attribution(tmp_path):
    db = tmp_path / "soc.db"
    events_path = ROOT / "examples/attack_chain.jsonl"
    upsert_case(
        db,
        new_case("HIST-1"),
        title="Historical incident",
        evidence_path=events_path,
    )

    matches = find_similar_cases(load_jsonl(events_path), db)
    assert matches
    assert all("attacker" not in " ".join(item.explanation).lower() for item in matches)
