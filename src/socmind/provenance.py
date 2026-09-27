from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True, slots=True)
class EvidenceProvenance:
    path: str
    sha256: str
    size_bytes: int


def fingerprint(path: str | Path) -> EvidenceProvenance:
    source = Path(path)
    digest = sha256()
    with source.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return EvidenceProvenance(str(source), digest.hexdigest(), source.stat().st_size)
