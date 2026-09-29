from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


MANIFEST_VERSION = 1


@dataclass(frozen=True, slots=True)
class EvidenceVerification:
    evidence_path: str
    manifest_path: str
    valid: bool
    expected_sha256: str
    actual_sha256: str
    expected_size: int
    actual_size: int
    expected_event_count: int
    actual_event_count: int
    errors: tuple[str, ...]


def evidence_manifest_path(evidence_path: str | Path) -> Path:
    path = Path(evidence_path)
    return Path(str(path) + ".manifest.json")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _count_jsonl_events(path: Path) -> int:
    with path.open("r", encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def write_evidence_manifest(
    evidence_path: str | Path,
    *,
    case_id: str,
    source: str,
    event_count: int | None = None,
    collected_at: str | None = None,
) -> Path:
    evidence = Path(evidence_path)
    if not evidence.is_file():
        raise FileNotFoundError(evidence)

    count = _count_jsonl_events(evidence) if event_count is None else int(event_count)
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "case_id": str(case_id),
        "file_name": evidence.name,
        "sha256": sha256_file(evidence),
        "size_bytes": evidence.stat().st_size,
        "collected_at": collected_at or datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "event_count": count,
    }

    target = evidence_manifest_path(evidence)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + f".{os.getpid()}.tmp")
    with temp.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    temp.replace(target)
    return target


def verify_evidence_manifest(
    evidence_path: str | Path,
    manifest_path: str | Path | None = None,
) -> EvidenceVerification:
    evidence = Path(evidence_path)
    manifest_file = Path(manifest_path) if manifest_path else evidence_manifest_path(evidence)
    if not evidence.is_file():
        raise FileNotFoundError(evidence)
    if not manifest_file.is_file():
        raise FileNotFoundError(manifest_file)

    payload = json.loads(manifest_file.read_text(encoding="utf-8"))
    expected_sha = str(payload.get("sha256") or "")
    expected_size = int(payload.get("size_bytes", -1))
    expected_count = int(payload.get("event_count", -1))

    actual_sha = sha256_file(evidence)
    actual_size = evidence.stat().st_size
    actual_count = _count_jsonl_events(evidence)
    errors: list[str] = []

    if payload.get("manifest_version") != MANIFEST_VERSION:
        errors.append("unsupported manifest_version")
    if payload.get("file_name") != evidence.name:
        errors.append("file_name mismatch")
    if expected_sha != actual_sha:
        errors.append("sha256 mismatch")
    if expected_size != actual_size:
        errors.append("size mismatch")
    if expected_count != actual_count:
        errors.append("event_count mismatch")

    return EvidenceVerification(
        evidence_path=str(evidence.resolve()),
        manifest_path=str(manifest_file.resolve()),
        valid=not errors,
        expected_sha256=expected_sha,
        actual_sha256=actual_sha,
        expected_size=expected_size,
        actual_size=actual_size,
        expected_event_count=expected_count,
        actual_event_count=actual_count,
        errors=tuple(errors),
    )


def verification_payload(result: EvidenceVerification) -> dict:
    return asdict(result)
