from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .ioc import IOC


@dataclass(frozen=True, slots=True)
class EnrichmentResult:
    type: str
    value: str
    provider: str
    verdict: str
    confidence: int
    context: str | None = None


class EnrichmentProvider:
    name = "provider"

    def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        raise NotImplementedError


class LocalIntelProvider(EnrichmentProvider):
    """Offline provider backed by a local JSON intelligence file."""

    name = "local-intel"

    def __init__(self, path: str | Path):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        self.records = {
            (str(item["type"]).lower(), str(item["value"]).lower()): item
            for item in raw.get("indicators", [])
        }

    def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        item = self.records.get((ioc.type.lower(), ioc.value.lower()))
        if not item:
            return None
        return EnrichmentResult(
            type=ioc.type,
            value=ioc.value,
            provider=self.name,
            verdict=str(item.get("verdict", "unknown")),
            confidence=int(item.get("confidence", 0)),
            context=item.get("context"),
        )


def enrich_iocs(iocs: list[IOC], providers: list[EnrichmentProvider]) -> list[EnrichmentResult]:
    results: list[EnrichmentResult] = []
    for ioc in iocs:
        for provider in providers:
            result = provider.enrich(ioc)
            if result is not None:
                results.append(result)
    return results
