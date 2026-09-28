from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from .http_client import JSONHTTPClient, basic_auth


@dataclass(frozen=True, slots=True)
class IntegrationStatus:
    provider: str
    ok: bool
    detail: str


class WazuhClient:
    def __init__(
        self,
        base_url: str,
        *,
        username: str,
        password: str,
        verify_tls: bool = True,
        timeout: float = 20.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.http = JSONHTTPClient(verify_tls=verify_tls, timeout=timeout)
        self.token: str | None = None

    def authenticate(self) -> str:
        response = self.http.request(
            "POST",
            f"{self.base_url}/security/user/authenticate?raw=true",
            headers={"Authorization": basic_auth(self.username, self.password)},
        )
        raw = response.body.decode("utf-8").strip()
        if raw.startswith("{"):
            payload = json.loads(raw)
            raw = payload.get("data", {}).get("token", "")
        if not raw:
            raise RuntimeError("Wazuh authentication returned no token")
        self.token = raw
        return raw

    def _headers(self) -> dict[str, str]:
        token = self.token or self.authenticate()
        return {"Authorization": f"Bearer {token}"}

    def server_info(self) -> dict:
        return self.http.request(
            "GET",
            f"{self.base_url}/?pretty=false",
            headers=self._headers(),
        ).json()

    def agents(self, *, limit: int = 100) -> dict:
        return self.http.request(
            "GET",
            f"{self.base_url}/agents?limit={int(limit)}",
            headers=self._headers(),
        ).json()


class ElasticClient:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        bearer_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool = True,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.http = JSONHTTPClient(verify_tls=verify_tls, timeout=timeout)
        if api_key:
            self.authorization = f"ApiKey {api_key}"
        elif bearer_token:
            self.authorization = f"Bearer {bearer_token}"
        elif username is not None and password is not None:
            self.authorization = basic_auth(username, password)
        else:
            self.authorization = None

    def search(
        self,
        index: str,
        *,
        query: dict | None = None,
        size: int = 100,
        sort: list | None = None,
    ) -> dict:
        headers = {}
        if self.authorization:
            headers["Authorization"] = self.authorization
        payload: dict = {
            "size": min(max(int(size), 1), 10000),
            "query": query or {"match_all": {}},
        }
        if sort:
            payload["sort"] = sort
        safe_index = quote(index, safe="*,-_:.")
        return self.http.request(
            "POST",
            f"{self.base_url}/{safe_index}/_search",
            headers=headers,
            json_body=payload,
        ).json()

    def export_ndjson(
        self,
        index: str,
        output: str | Path,
        *,
        query: dict | None = None,
        size: int = 100,
        sort: list | None = None,
    ) -> int:
        response = self.search(index, query=query, size=size, sort=sort)
        hits = response.get("hits", {}).get("hits", [])
        target = Path(output)
        with target.open("w", encoding="utf-8") as fh:
            for hit in hits:
                fh.write(json.dumps(hit, ensure_ascii=False) + "\n")
        return len(hits)


def integration_check(provider: str, client) -> IntegrationStatus:
    try:
        if provider == "wazuh":
            info = client.server_info()
            detail = "Wazuh API authenticated"
            if isinstance(info, dict):
                affected = info.get("data", {}).get("affected_items", [])
                if affected:
                    version = affected[0].get("version")
                    if version:
                        detail += f" · version={version}"
            return IntegrationStatus(provider, True, detail)
        if provider == "elastic":
            response = client.http.request(
                "GET",
                f"{client.base_url}/",
                headers={"Authorization": client.authorization} if client.authorization else {},
            ).json()
            version = response.get("version", {}).get("number", "unknown")
            return IntegrationStatus(provider, True, f"Elasticsearch reachable · version={version}")
        raise ValueError(f"Unknown provider: {provider}")
    except Exception as exc:
        return IntegrationStatus(provider, False, str(exc))
