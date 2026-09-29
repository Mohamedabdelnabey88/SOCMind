from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile

from .detection_replay import replay_detection
from .detections import load_rule
from .io import load_jsonl
from .rbac import Principal, normalize_role, require_permission
from .rule_tests import run_rule_test


RULE_LIFECYCLE_STATUSES = (
    "experimental",
    "testing",
    "approved",
    "production",
    "deprecated",
    "retired",
)

RULE_TRANSITIONS = {
    "experimental": {"testing"},
    "testing": {"experimental", "approved"},
    "approved": {"testing", "production"},
    "production": {"deprecated"},
    "deprecated": {"production", "retired"},
    "retired": set(),
}

REGISTRY_SCHEMA_VERSION = 1
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty_registry() -> dict:
    return {"schema_version": REGISTRY_SCHEMA_VERSION, "rules": {}}


def _safe_registry_path(path: str | Path) -> Path:
    target = Path(path)
    if target.exists() and target.is_symlink():
        raise ValueError("Rule lifecycle registry must not be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink():
        raise ValueError("Rule lifecycle registry parent must not be a symlink")
    return target


@contextmanager
def _registry_lock(target: Path):
    lock_path = target.with_suffix(target.suffix + ".lock")
    if lock_path.exists() and lock_path.is_symlink():
        raise ValueError("Rule lifecycle registry lock must not be a symlink")
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    with lock_path.open("a+b") as fh:
        if fh.seek(0, os.SEEK_END) == 0:
            fh.write(b"0")
            fh.flush()
            os.fsync(fh.fileno())
        fh.seek(0)

        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _load_unlocked(target: Path) -> dict:
    if not target.exists():
        return _empty_registry()
    raw = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Rule lifecycle registry must be a JSON object")
    if int(raw.get("schema_version", 0)) != REGISTRY_SCHEMA_VERSION:
        raise ValueError("Unsupported rule lifecycle registry version")
    rules = raw.get("rules")
    if not isinstance(rules, dict):
        raise ValueError("Rule lifecycle registry rules must be a JSON object")
    return raw


def load_rule_registry(path: str | Path) -> dict:
    target = _safe_registry_path(path)
    with _registry_lock(target):
        return deepcopy(_load_unlocked(target))


def _atomic_write(target: Path, payload: dict) -> None:
    encoded = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(
        prefix=target.name + ".",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_name, target)
        if os.name != "nt":
            directory_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _mutate_registry(path: str | Path, operation):
    target = _safe_registry_path(path)
    with _registry_lock(target):
        registry = _load_unlocked(target)
        result = operation(registry)
        _atomic_write(target, registry)
        return deepcopy(result)


def _principal(actor: str, role: str) -> Principal:
    clean_actor = str(actor or "").strip()
    if not clean_actor:
        raise ValueError("Actor is required")
    if len(clean_actor) > 120:
        raise ValueError("Actor must be 120 characters or fewer")
    clean_role = normalize_role(role)
    return Principal(clean_actor, clean_role, "local-cli")


def _require_rule(registry: dict, rule_id: str) -> dict:
    record = registry["rules"].get(rule_id)
    if record is None:
        raise ValueError(f"Unknown registered rule: {rule_id}")
    return record


def _history(
    record: dict,
    *,
    actor: str,
    action: str,
    note: str,
    from_status: str | None = None,
    to_status: str | None = None,
) -> None:
    now = _utc_now()
    record["updated_at"] = now
    record.setdefault("history", []).append({
        "timestamp": now,
        "actor": actor,
        "action": action,
        "from_status": from_status,
        "to_status": to_status,
        "note": note,
    })


def _validate_version(version: str) -> str:
    clean = str(version or "").strip()
    if not _SEMVER.fullmatch(clean):
        raise ValueError("Rule version must use semantic version format X.Y.Z")
    return clean


def register_rule(
    registry_path: str | Path,
    rule_path: str | Path,
    *,
    owner: str,
    actor: str,
    role: str,
    version: str = "1.0.0",
    note: str = "Initial lifecycle registration",
) -> dict:
    principal = _principal(actor, role)
    require_permission(principal, "detection.manage")
    clean_owner = str(owner or "").strip()
    if not clean_owner:
        raise ValueError("Rule owner is required")
    if len(clean_owner) > 120:
        raise ValueError("Rule owner must be 120 characters or fewer")
    clean_version = _validate_version(version)

    source = Path(rule_path)
    if source.is_symlink():
        raise ValueError("Detection rule source must not be a symlink")
    rule = load_rule(source)
    status = rule.status if rule.status in RULE_LIFECYCLE_STATUSES else "experimental"
    now = _utc_now()

    def operation(registry):
        if rule.id in registry["rules"]:
            raise ValueError(f"Rule already registered: {rule.id}")
        record = {
            "rule_id": rule.id,
            "rule_path": str(source.resolve()),
            "title": rule.title,
            "version": clean_version,
            "owner": clean_owner,
            "created_at": now,
            "updated_at": now,
            "status": status,
            "change_notes": [{
                "timestamp": now,
                "actor": principal.subject,
                "version": clean_version,
                "note": str(note or "").strip() or "Initial lifecycle registration",
            }],
            "attack_mapping": rule.attack_techniques,
            "syntax_status": {
                "status": "passed",
                "checked_at": now,
                "actor": principal.subject,
                "error": None,
            },
            "test_status": {
                "status": "not-run",
                "tested_at": None,
                "actor": None,
                "fixture": None,
                "expected_matches": None,
                "actual_matches": None,
            },
            "false_positive_history": [],
            "replay_results": [],
            "coverage_history": [],
            "history": [{
                "timestamp": now,
                "actor": principal.subject,
                "action": "registered",
                "from_status": None,
                "to_status": status,
                "note": str(note or "").strip() or "Initial lifecycle registration",
            }],
        }
        registry["rules"][rule.id] = record
        return record

    return _mutate_registry(registry_path, operation)


def validate_registered_rule_syntax(
    registry_path: str | Path,
    rule_id: str,
    *,
    actor: str,
    role: str,
) -> dict:
    principal = _principal(actor, role)
    require_permission(principal, "detection.manage")

    def operation(registry):
        record = _require_rule(registry, rule_id)
        now = _utc_now()
        try:
            rule = load_rule(record["rule_path"])
            error = None
            status = "passed"
            record["title"] = rule.title
            record["attack_mapping"] = rule.attack_techniques
        except Exception as exc:
            status = "failed"
            error = str(exc)
        record["syntax_status"] = {
            "status": status,
            "checked_at": now,
            "actor": principal.subject,
            "error": error,
        }
        _history(
            record,
            actor=principal.subject,
            action="syntax-validation",
            note=error or "Syntax validation passed",
        )
        return record["syntax_status"]

    return _mutate_registry(registry_path, operation)


def test_registered_rule(
    registry_path: str | Path,
    rule_id: str,
    fixture: str | Path,
    *,
    actor: str,
    role: str,
) -> dict:
    principal = _principal(actor, role)
    require_permission(principal, "detection.manage")

    def operation(registry):
        record = _require_rule(registry, rule_id)
        rule = load_rule(record["rule_path"])
        result = run_rule_test(rule, fixture)
        payload = {
            "status": "passed" if result.passed else "failed",
            "tested_at": _utc_now(),
            "actor": principal.subject,
            "fixture": str(Path(fixture).resolve()),
            "name": result.name,
            "expected_matches": result.expected_matches,
            "actual_matches": result.actual_matches,
        }
        record["test_status"] = payload
        _history(
            record,
            actor=principal.subject,
            action="regression-test",
            note=(
                f"{payload['status']} · expected={result.expected_matches} "
                f"actual={result.actual_matches}"
            ),
        )
        return payload

    return _mutate_registry(registry_path, operation)


def record_incident_replay(
    registry_path: str | Path,
    rule_id: str,
    events_path: str | Path,
    *,
    actor: str,
    role: str,
    case_id: str | None = None,
) -> dict:
    principal = _principal(actor, role)
    require_permission(principal, "detection.manage")
    events = load_jsonl(events_path)

    def operation(registry):
        record = _require_rule(registry, rule_id)
        rule = load_rule(record["rule_path"])
        replay = replay_detection(events, [rule])
        payload = {
            "timestamp": _utc_now(),
            "actor": principal.subject,
            "case_id": case_id,
            "events_path": str(Path(events_path).resolve()),
            "events": len(events),
            "first_detection_step": replay.first_detection_step,
            "visibility_percent": replay.visibility_percent,
            "observed_techniques": replay.observed_techniques,
            "covered_techniques": replay.covered_techniques,
            "gap_techniques": replay.gap_techniques,
            "blind_steps_before_first_detection": replay.blind_steps_before_first_detection,
        }
        record.setdefault("replay_results", []).append(payload)
        _history(
            record,
            actor=principal.subject,
            action="incident-replay",
            note=(
                f"visibility={replay.visibility_percent}% "
                f"first_detection_step={replay.first_detection_step}"
            ),
        )
        return payload

    return _mutate_registry(registry_path, operation)


def record_false_positive_observation(
    registry_path: str | Path,
    rule_id: str,
    *,
    actor: str,
    role: str,
    sample_size: int,
    false_positives: int,
    note: str,
) -> dict:
    principal = _principal(actor, role)
    require_permission(principal, "detection.manage")
    sample = int(sample_size)
    fp = int(false_positives)
    if sample <= 0:
        raise ValueError("False-positive sample size must be greater than zero")
    if fp < 0 or fp > sample:
        raise ValueError("False-positive count must be between zero and sample size")
    clean_note = str(note or "").strip()
    if not clean_note:
        raise ValueError("False-positive observation note is required")

    def operation(registry):
        record = _require_rule(registry, rule_id)
        payload = {
            "timestamp": _utc_now(),
            "actor": principal.subject,
            "sample_size": sample,
            "false_positives": fp,
            "false_positive_rate": round(fp / sample, 6),
            "note": clean_note,
        }
        record.setdefault("false_positive_history", []).append(payload)
        _history(
            record,
            actor=principal.subject,
            action="false-positive-observation",
            note=f"{fp}/{sample} false positives · {clean_note}",
        )
        return payload

    return _mutate_registry(registry_path, operation)


def record_coverage_delta(
    registry_path: str | Path,
    rule_id: str,
    *,
    actor: str,
    role: str,
    visibility_delta: float,
    newly_covered_techniques: list[str] | None = None,
    note: str = "",
) -> dict:
    principal = _principal(actor, role)
    require_permission(principal, "detection.manage")
    techniques = sorted({
        str(item).strip().upper()
        for item in (newly_covered_techniques or [])
        if str(item).strip()
    })

    def operation(registry):
        record = _require_rule(registry, rule_id)
        payload = {
            "timestamp": _utc_now(),
            "actor": principal.subject,
            "visibility_delta": float(visibility_delta),
            "newly_covered_techniques": techniques,
            "note": str(note or "").strip(),
        }
        record.setdefault("coverage_history", []).append(payload)
        _history(
            record,
            actor=principal.subject,
            action="coverage-delta",
            note=(
                f"visibility_delta={payload['visibility_delta']} "
                f"new_coverage={','.join(techniques) or '-'}"
            ),
        )
        return payload

    return _mutate_registry(registry_path, operation)


def update_rule_version(
    registry_path: str | Path,
    rule_id: str,
    *,
    version: str,
    actor: str,
    role: str,
    note: str,
) -> dict:
    principal = _principal(actor, role)
    require_permission(principal, "detection.manage")
    clean_version = _validate_version(version)
    clean_note = str(note or "").strip()
    if not clean_note:
        raise ValueError("Version change note is required")

    def operation(registry):
        record = _require_rule(registry, rule_id)
        previous = record["version"]
        if clean_version == previous:
            raise ValueError("New rule version must differ from current version")
        record["version"] = clean_version
        record.setdefault("change_notes", []).append({
            "timestamp": _utc_now(),
            "actor": principal.subject,
            "version": clean_version,
            "note": clean_note,
        })
        _history(
            record,
            actor=principal.subject,
            action="version-change",
            note=f"{previous} -> {clean_version} · {clean_note}",
        )
        return record

    return _mutate_registry(registry_path, operation)


def approval_gaps(record: dict) -> list[str]:
    gaps: list[str] = []
    if record.get("syntax_status", {}).get("status") != "passed":
        gaps.append("syntax validation has not passed")
    if record.get("test_status", {}).get("status") != "passed":
        gaps.append("regression fixture test has not passed")
    if not record.get("replay_results"):
        gaps.append("confirmed-incident replay has not been recorded")
    if not record.get("false_positive_history"):
        gaps.append("false-positive observation has not been recorded")
    if not record.get("coverage_history"):
        gaps.append("coverage delta has not been recorded")
    return gaps


def transition_rule(
    registry_path: str | Path,
    rule_id: str,
    target: str,
    *,
    actor: str,
    role: str,
    note: str,
) -> dict:
    principal = _principal(actor, role)
    target = str(target or "").strip().lower()
    if target not in RULE_LIFECYCLE_STATUSES:
        raise ValueError(f"Unknown rule lifecycle status: {target}")

    permission = "detection.manage"
    if target in {"approved", "deprecated", "retired"}:
        permission = "detection.approve"
    elif target == "production":
        permission = "detection.promote"
    require_permission(principal, permission)

    clean_note = str(note or "").strip()
    if not clean_note:
        raise ValueError("Lifecycle transition note is required")

    def operation(registry):
        record = _require_rule(registry, rule_id)
        current = record["status"]
        if target not in RULE_TRANSITIONS.get(current, set()):
            raise ValueError(f"Invalid rule transition: {current} -> {target}")
        if target in {"approved", "production"}:
            gaps = approval_gaps(record)
            if gaps:
                raise ValueError(
                    "Rule cannot be promoted; " + "; ".join(gaps)
                )
        record["status"] = target
        _history(
            record,
            actor=principal.subject,
            action="status-transition",
            note=clean_note,
            from_status=current,
            to_status=target,
        )
        return record

    return _mutate_registry(registry_path, operation)


def rule_lifecycle_detail(registry_path: str | Path, rule_id: str) -> dict:
    registry = load_rule_registry(registry_path)
    return deepcopy(_require_rule(registry, rule_id))


def rule_lifecycle_list(registry_path: str | Path) -> list[dict]:
    registry = load_rule_registry(registry_path)
    return [
        deepcopy(registry["rules"][key])
        for key in sorted(registry["rules"])
    ]
