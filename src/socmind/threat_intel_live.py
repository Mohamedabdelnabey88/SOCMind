from __future__ import annotations

from .enrichment import EnrichmentProvider, EnrichmentResult
from .http_client import JSONHTTPClient
from .ioc import IOC


class MISPProvider(EnrichmentProvider):
    name = "misp"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        verify_tls: bool = True,
        timeout: float = 20.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.http = JSONHTTPClient(verify_tls=verify_tls, timeout=timeout)

    def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        response = self.http.request(
            "POST",
            f"{self.base_url}/attributes/restSearch",
            headers={
                "Authorization": self.api_key,
                "Accept": "application/json",
            },
            json_body={
                "returnFormat": "json",
                "value": ioc.value,
                "limit": 10,
            },
        ).json()

        response_block = response.get("response", response)
        if isinstance(response_block, dict):
            attributes = response_block.get("Attribute", [])
        elif isinstance(response_block, list):
            attributes = response_block
        else:
            attributes = []

        matches = [
            item for item in attributes
            if str(item.get("value", "")).lower() == ioc.value.lower()
        ]
        if not matches:
            return None

        tags = []
        for item in matches:
            for tag in item.get("Tag", []) or []:
                name = tag.get("name")
                if name:
                    tags.append(name)
        context = f"{len(matches)} exact MISP attribute match(es)"
        if tags:
            context += " · tags=" + ",".join(sorted(set(tags))[:5])

        return EnrichmentResult(
            type=ioc.type,
            value=ioc.value,
            provider=self.name,
            verdict="known-intel",
            confidence=min(95, 65 + min(len(matches), 6) * 5),
            context=context,
        )


class OpenCTIClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        verify_tls: bool = True,
        timeout: float = 20.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.http = JSONHTTPClient(verify_tls=verify_tls, timeout=timeout)

    def graphql(self, query: str, variables: dict | None = None) -> dict:
        payload = self.http.request(
            "POST",
            f"{self.base_url}/graphql",
            headers={"Authorization": f"Bearer {self.token}"},
            json_body={"query": query, "variables": variables or {}},
        ).json()
        if payload.get("errors"):
            raise RuntimeError(f"OpenCTI GraphQL error: {payload['errors'][0]}")
        return payload.get("data", {})
