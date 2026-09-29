from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from .rbac import normalize_role


DEFAULT_SCOPES = "openid profile email"
ALLOWED_ID_TOKEN_ALGORITHMS = ("RS256", "PS256", "ES256")
ROLE_ORDER = {
    "viewer": 0,
    "analyst": 1,
    "senior-analyst": 2,
    "lead": 3,
    "admin": 4,
}


@dataclass(frozen=True, slots=True)
class OIDCConfig:
    issuer: str
    client_id: str
    redirect_uri: str
    session_secret: str
    client_secret: str | None = None
    role_claim: str = "groups"
    role_map: dict[str, str] | None = None
    default_role: str = "viewer"
    subject_claim: str = "sub"
    scopes: str = DEFAULT_SCOPES
    session_cookie: str = "socmind_oidc_session"
    transaction_cookie: str = "socmind_oidc_transaction"
    session_ttl_seconds: int = 8 * 60 * 60
    allow_insecure_http: bool = False


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _require_https(value: str, *, allow_insecure_http: bool) -> str:
    parsed = urlparse(value)
    if parsed.scheme == "https":
        return value
    if allow_insecure_http and parsed.scheme == "http" and parsed.hostname in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        return value
    raise ValueError("OIDC endpoints must use HTTPS (HTTP is allowed only for loopback development)")


def normalize_issuer(issuer: str, *, allow_insecure_http: bool = False) -> str:
    clean = str(issuer or "").strip().rstrip("/")
    if not clean:
        raise ValueError("OIDC issuer is required")
    return _require_https(clean, allow_insecure_http=allow_insecure_http)


def discovery_url(issuer: str, *, allow_insecure_http: bool = False) -> str:
    clean = normalize_issuer(issuer, allow_insecure_http=allow_insecure_http)
    return clean + "/.well-known/openid-configuration"


def _json_request(
    url: str,
    *,
    method: str = "GET",
    data: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> dict:
    body = None
    headers = {"Accept": "application/json"}
    if data is not None:
        body = urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = Request(url, data=body, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as response:
        raw = response.read()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("OIDC endpoint returned a non-object JSON response")
    return payload


def validate_oidc_config(config: OIDCConfig) -> OIDCConfig:
    normalize_issuer(
        config.issuer,
        allow_insecure_http=config.allow_insecure_http,
    )
    if not str(config.client_id or "").strip():
        raise ValueError("OIDC client ID is required")
    if len(str(config.session_secret or "")) < 32:
        raise ValueError("OIDC session secret must be at least 32 characters")
    _require_https(
        str(config.redirect_uri or ""),
        allow_insecure_http=config.allow_insecure_http,
    )
    scopes = {item for item in str(config.scopes or "").split() if item}
    if "openid" not in scopes:
        raise ValueError("OIDC scopes must include 'openid'")
    parse_role_map(config.role_map)
    normalize_role(config.default_role)
    return config


def fetch_discovery(config: OIDCConfig) -> dict:
    url = discovery_url(
        config.issuer,
        allow_insecure_http=config.allow_insecure_http,
    )
    payload = _json_request(url)
    issuer = normalize_issuer(
        str(payload.get("issuer") or ""),
        allow_insecure_http=config.allow_insecure_http,
    )
    expected = normalize_issuer(
        config.issuer,
        allow_insecure_http=config.allow_insecure_http,
    )
    if issuer != expected:
        raise ValueError("OIDC discovery issuer does not match configured issuer")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = str(payload.get(key) or "")
        if not value:
            raise ValueError(f"OIDC discovery is missing {key}")
        _require_https(value, allow_insecure_http=config.allow_insecure_http)
    return payload


def parse_role_map(raw: str | dict[str, str] | None) -> dict[str, str]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        source = raw
    else:
        text = str(raw).strip()
        if not text:
            return {}
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("OIDC role map must be a JSON object")
        source = parsed
    result: dict[str, str] = {}
    for key, value in source.items():
        claim_value = str(key).strip()
        if not claim_value:
            continue
        result[claim_value] = normalize_role(str(value))
    return result


def map_claims_to_role(
    claims: dict[str, Any],
    *,
    claim_name: str,
    role_map: dict[str, str] | None,
    default_role: str,
) -> str:
    mapping = parse_role_map(role_map)
    value = claims.get(claim_name)
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = [str(item) for item in value]
    elif value is None:
        values = []
    else:
        values = [str(value)]
    mapped = [
        normalize_role(mapping[item])
        for item in values
        if item in mapping
    ]
    if not mapped:
        return normalize_role(default_role)
    return max(mapped, key=lambda role: ROLE_ORDER[role])


def _sign(payload: bytes, secret: str) -> str:
    return _b64url(hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest())


def encode_signed_payload(payload: dict, secret: str) -> str:
    if len(secret) < 32:
        raise ValueError("OIDC session secret must be at least 32 characters")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded = _b64url(raw)
    signature = _sign(encoded.encode("ascii"), secret)
    return encoded + "." + signature


def decode_signed_payload(value: str, secret: str, *, now: int | None = None) -> dict:
    if len(secret) < 32:
        raise ValueError("OIDC session secret must be at least 32 characters")
    encoded, separator, supplied = str(value or "").partition(".")
    if not separator or not encoded or not supplied:
        raise PermissionError("Invalid OIDC session")
    expected = _sign(encoded.encode("ascii"), secret)
    if not secrets.compare_digest(supplied, expected):
        raise PermissionError("Invalid OIDC session signature")
    try:
        payload = json.loads(_b64url_decode(encoded))
    except (ValueError, json.JSONDecodeError) as exc:
        raise PermissionError("Invalid OIDC session payload") from exc
    if not isinstance(payload, dict):
        raise PermissionError("Invalid OIDC session payload")
    current = int(time.time()) if now is None else int(now)
    if int(payload.get("exp", 0)) <= current:
        raise PermissionError("OIDC session has expired")
    return payload


def new_authorization_transaction(
    config: OIDCConfig,
    *,
    return_to: str = "/",
    now: int | None = None,
) -> tuple[str, str]:
    current = int(time.time()) if now is None else int(now)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    transaction = {
        "state": state,
        "nonce": nonce,
        "verifier": verifier,
        "return_to": return_to if str(return_to).startswith("/") else "/",
        "exp": current + 600,
    }
    cookie = encode_signed_payload(transaction, config.session_secret)
    return cookie, challenge


def build_authorization_url(
    config: OIDCConfig,
    discovery: dict,
    transaction_cookie: str,
    challenge: str,
) -> str:
    transaction = decode_signed_payload(transaction_cookie, config.session_secret)
    endpoint = _require_https(
        str(discovery["authorization_endpoint"]),
        allow_insecure_http=config.allow_insecure_http,
    )
    params = {
        "client_id": config.client_id,
        "response_type": "code",
        "scope": config.scopes,
        "redirect_uri": config.redirect_uri,
        "state": transaction["state"],
        "nonce": transaction["nonce"],
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)


def exchange_code(
    config: OIDCConfig,
    discovery: dict,
    *,
    code: str,
    verifier: str,
) -> dict:
    endpoint = _require_https(
        str(discovery["token_endpoint"]),
        allow_insecure_http=config.allow_insecure_http,
    )
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_uri,
        "client_id": config.client_id,
        "code_verifier": verifier,
    }
    if config.client_secret:
        data["client_secret"] = config.client_secret
    payload = _json_request(endpoint, method="POST", data=data)
    if not payload.get("id_token"):
        raise PermissionError("OIDC token response did not include an ID token")
    return payload


def verify_id_token(
    config: OIDCConfig,
    discovery: dict,
    id_token: str,
    *,
    nonce: str,
) -> dict:
    try:
        import jwt
    except ImportError as exc:
        raise RuntimeError(
            "OIDC authentication requires PyJWT with crypto support"
        ) from exc

    jwks_uri = _require_https(
        str(discovery["jwks_uri"]),
        allow_insecure_http=config.allow_insecure_http,
    )
    try:
        header = jwt.get_unverified_header(id_token)
        algorithm = str(header.get("alg") or "")
        if algorithm not in ALLOWED_ID_TOKEN_ALGORITHMS:
            raise PermissionError(
                f"Unsupported OIDC ID-token algorithm: {algorithm}"
            )

        jwk_client = jwt.PyJWKClient(jwks_uri, cache_keys=True)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=[algorithm],
            audience=config.client_id,
            issuer=normalize_issuer(
                config.issuer,
                allow_insecure_http=config.allow_insecure_http,
            ),
            options={
                "require": ["exp", "iat", "iss", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except PermissionError:
        raise
    except jwt.PyJWTError as exc:
        raise PermissionError(f"OIDC ID-token validation failed: {exc}") from exc

    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1:
        if not secrets.compare_digest(
            str(claims.get("azp") or ""),
            str(config.client_id),
        ):
            raise PermissionError(
                "OIDC authorized-party claim does not match client ID"
            )
    if not secrets.compare_digest(str(claims.get("nonce") or ""), str(nonce)):
        raise PermissionError("OIDC nonce validation failed")
    return dict(claims)


def session_from_claims(
    config: OIDCConfig,
    claims: dict,
    *,
    now: int | None = None,
) -> tuple[str, dict]:
    current = int(time.time()) if now is None else int(now)
    subject = str(claims.get(config.subject_claim) or "").strip()
    if not subject:
        raise PermissionError(
            f"OIDC token is missing subject claim {config.subject_claim!r}"
        )
    role = map_claims_to_role(
        claims,
        claim_name=config.role_claim,
        role_map=config.role_map,
        default_role=config.default_role,
    )
    token_exp = int(claims.get("exp", current + config.session_ttl_seconds))
    expires = min(token_exp, current + max(60, config.session_ttl_seconds))
    payload = {
        "sub": subject,
        "role": role,
        "iss": str(claims.get("iss") or ""),
        "iat": current,
        "exp": expires,
    }
    return encode_signed_payload(payload, config.session_secret), payload
