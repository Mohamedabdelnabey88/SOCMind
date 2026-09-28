from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from .rbac import Principal, normalize_role


@dataclass(frozen=True, slots=True)
class AuthConfig:
    mode: str = "local-token"
    api_token: str | None = None
    api_token_role: str = "admin"
    trusted_proxy_secret: str | None = None
    trusted_subject_header: str = "x-socmind-user"
    trusted_role_header: str = "x-socmind-role"
    trusted_timestamp_header: str = "x-socmind-timestamp"
    trusted_signature_header: str = "x-socmind-signature"
    trusted_max_skew_seconds: int = 90


def _proxy_signature(
    secret: str,
    subject: str,
    role: str,
    timestamp: str,
) -> str:
    message = f"{subject}\n{role}\n{timestamp}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def authenticate(
    headers: dict[str, str],
    config: AuthConfig,
) -> Principal:
    mode = config.mode.strip().lower()

    if mode == "local-token":
        expected = config.api_token
        if not expected:
            return Principal("local-analyst", "admin", "loopback-local")
        supplied = headers.get("x-socmind-token")
        if not supplied or not secrets.compare_digest(supplied, expected):
            raise PermissionError("Invalid SOCMind API token")
        return Principal(
            "token-user",
            normalize_role(config.api_token_role, default="admin"),
            "local-token",
        )

    if mode == "trusted-proxy":
        secret = config.trusted_proxy_secret
        if not secret:
            raise PermissionError("Trusted proxy authentication is not configured")

        subject = headers.get(config.trusted_subject_header.lower(), "").strip()
        role = headers.get(config.trusted_role_header.lower(), "").strip()
        timestamp = headers.get(
            config.trusted_timestamp_header.lower(), ""
        ).strip()
        signature = headers.get(
            config.trusted_signature_header.lower(), ""
        ).strip()
        if not subject or not role or not timestamp or not signature:
            raise PermissionError("Missing trusted proxy identity headers")

        try:
            signed_at = int(timestamp)
        except ValueError as exc:
            raise PermissionError("Invalid trusted proxy timestamp") from exc

        now = int(time.time())
        if abs(now - signed_at) > max(1, config.trusted_max_skew_seconds):
            raise PermissionError("Trusted proxy identity signature has expired")

        normalized_role = normalize_role(role)
        expected = _proxy_signature(
            secret,
            subject,
            normalized_role,
            timestamp,
        )
        if not secrets.compare_digest(signature, expected):
            raise PermissionError("Invalid trusted proxy identity signature")

        return Principal(subject, normalized_role, "trusted-proxy")

    raise PermissionError(f"Unsupported authentication mode: {config.mode}")


def sign_trusted_proxy_identity(
    secret: str,
    subject: str,
    role: str,
    *,
    timestamp: int | str,
) -> str:
    normalized_role = normalize_role(role)
    return _proxy_signature(
        secret,
        subject,
        normalized_role,
        str(timestamp),
    )


def trusted_proxy_headers(
    secret: str,
    subject: str,
    role: str,
    *,
    timestamp: int | None = None,
) -> dict[str, str]:
    signed_at = int(time.time()) if timestamp is None else int(timestamp)
    normalized_role = normalize_role(role)
    stamp = str(signed_at)
    return {
        "X-SOCMind-User": subject,
        "X-SOCMind-Role": normalized_role,
        "X-SOCMind-Timestamp": stamp,
        "X-SOCMind-Signature": _proxy_signature(
            secret,
            subject,
            normalized_role,
            stamp,
        ),
    }
