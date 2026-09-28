from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


GENESIS = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditRecord:
    sequence: int
    timestamp: str
    case_id: str
    actor: str
    action: str
    detail: str
    previous_hash: str
    entry_hash: str


def _canonical_payload(
    sequence: int,
    timestamp: str,
    case_id: str,
    actor: str,
    action: str,
    detail: str,
    previous_hash: str,
) -> bytes:
    return json.dumps(
        {
            "sequence": sequence,
            "timestamp": timestamp,
            "case_id": case_id,
            "actor": actor,
            "action": action,
            "detail": detail,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hash_record(
    sequence: int,
    timestamp: str,
    case_id: str,
    actor: str,
    action: str,
    detail: str,
    previous_hash: str,
) -> str:
    return hashlib.sha256(
        _canonical_payload(
            sequence,
            timestamp,
            case_id,
            actor,
            action,
            detail,
            previous_hash,
        )
    ).hexdigest()


def append_record(
    path: str | Path,
    *,
    case_id: str,
    actor: str,
    action: str,
    detail: str,
    timestamp: str | None = None,
) -> AuditRecord:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = GENESIS
    sequence = 1
    if target.exists():
        lines = [line for line in target.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last = json.loads(lines[-1])
            previous_hash = last["entry_hash"]
            sequence = int(last["sequence"]) + 1

    ts = timestamp or datetime.now(timezone.utc).isoformat()
    entry_hash = hash_record(
        sequence, ts, case_id, actor, action, detail, previous_hash
    )
    record = AuditRecord(
        sequence,
        ts,
        case_id,
        actor,
        action,
        detail,
        previous_hash,
        entry_hash,
    )
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")
    return record


def verify_chain(path: str | Path) -> tuple[bool, int, str | None]:
    target = Path(path)
    if not target.exists():
        return True, 0, None

    previous_hash = GENESIS
    count = 0
    for raw in target.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        count += 1
        item = json.loads(raw)
        if item.get("previous_hash") != previous_hash:
            return False, count, "previous-hash mismatch"
        expected = hash_record(
            int(item["sequence"]),
            item["timestamp"],
            item["case_id"],
            item["actor"],
            item["action"],
            item["detail"],
            item["previous_hash"],
        )
        if not hmac_compare(item.get("entry_hash", ""), expected):
            return False, count, "entry-hash mismatch"
        previous_hash = item["entry_hash"]
    return True, count, None


def hmac_compare(left: str, right: str) -> bool:
    import hmac
    return hmac.compare_digest(left, right)
