from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_address
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SecurityCheck:
    name: str
    ok: bool
    detail: str


def is_loopback_host(host: str) -> bool:
    value = host.strip().lower()
    if value == "localhost":
        return True
    try:
        return ip_address(value).is_loopback
    except ValueError:
        return False


def validate_web_binding(
    host: str,
    *,
    api_token: str | None,
    allow_unsafe_remote: bool = False,
) -> None:
    if is_loopback_host(host):
        return
    if api_token:
        return
    if allow_unsafe_remote:
        return
    raise ValueError(
        "Refusing remote bind without API protection. "
        "Set SOCMIND_API_TOKEN/--api-token, bind to 127.0.0.1, "
        "or explicitly use --allow-unsafe-remote for an isolated lab."
    )


def security_report(
    *,
    host: str = "127.0.0.1",
    api_token: str | None = None,
    command_db: str | Path | None = None,
) -> list[SecurityCheck]:
    checks = [
        SecurityCheck(
            "web-binding",
            is_loopback_host(host) or bool(api_token),
            "loopback" if is_loopback_host(host) else (
                "token-protected remote bind" if api_token else "remote bind without token"
            ),
        ),
        SecurityCheck(
            "api-token",
            bool(api_token) or is_loopback_host(host),
            "configured" if api_token else "not required for loopback-only use",
        ),
    ]

    if command_db:
        path = Path(command_db)
        checks.append(
            SecurityCheck(
                "command-db",
                path.exists(),
                str(path.resolve()) if path.exists() else f"missing: {path}",
            )
        )
    return checks


def security_payload(**kwargs) -> list[dict]:
    return [asdict(item) for item in security_report(**kwargs)]
