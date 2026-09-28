from __future__ import annotations

import base64
import json
import ssl
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


@dataclass(frozen=True, slots=True)
class HTTPResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class HTTPClientError(RuntimeError):
    pass


class JSONHTTPClient:
    def __init__(self, *, verify_tls: bool = True, timeout: float = 20.0):
        self.timeout = timeout
        self.context = ssl.create_default_context()
        if not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict | list | None = None,
        body: bytes | None = None,
    ) -> HTTPResponse:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise HTTPClientError("Only http:// and https:// integration URLs are allowed")

        request_headers = {"Accept": "application/json", **(headers or {})}
        data = body
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")

        req = Request(url, data=data, headers=request_headers, method=method.upper())
        try:
            with urlopen(req, timeout=self.timeout, context=self.context) as response:
                return HTTPResponse(
                    status=response.status,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=response.read(),
                )
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise HTTPClientError(f"HTTP {exc.code}: {detail[:500]}") from exc
        except URLError as exc:
            raise HTTPClientError(f"Connection failed: {exc.reason}") from exc
        except OSError as exc:
            raise HTTPClientError(f"Connection failed: {exc}") from exc


def basic_auth(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"
