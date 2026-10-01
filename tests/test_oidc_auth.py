import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import socmind.oidc_auth as oidc
import socmind.webapp as webapp
from socmind.enterprise_auth import AuthConfig, authenticate
from socmind.oidc_auth import (
    OIDCConfig,
    decode_signed_payload,
    encode_signed_payload,
    exchange_code,
    map_claims_to_role,
    new_authorization_transaction,
    session_from_claims,
    validate_oidc_config,
    verify_id_token,
)


SECRET = "s" * 48


def _config(**overrides):
    values = {
        "issuer": "https://idp.example.test",
        "client_id": "socmind-client",
        "redirect_uri": "https://socmind.example.test/auth/callback",
        "session_secret": SECRET,
        "role_claim": "groups",
        "role_map": {
            "SOC-T1": "analyst",
            "SOC-T2": "senior-analyst",
            "SOC-Leads": "lead",
            "SOC-Admins": "admin",
        },
        "default_role": "viewer",
    }
    values.update(overrides)
    return OIDCConfig(**values)


def test_role_mapping_uses_highest_mapped_soc_role():
    role = map_claims_to_role(
        {"groups": ["SOC-T1", "SOC-Leads", "unmapped"]},
        claim_name="groups",
        role_map=_config().role_map,
        default_role="viewer",
    )
    assert role == "lead"


def test_oidc_config_rejects_non_https_non_loopback():
    with pytest.raises(ValueError, match="HTTPS"):
        validate_oidc_config(_config(issuer="http://idp.example.test"))

    local = _config(
        issuer="http://localhost:8080",
        redirect_uri="http://localhost:8765/auth/callback",
        allow_insecure_http=True,
    )
    assert validate_oidc_config(local) is local


def test_authorization_transaction_rejects_protocol_relative_return_path():
    config = _config()
    cookie, _ = new_authorization_transaction(
        config,
        return_to="//evil.example",
        now=1_900_000_000,
    )
    transaction = decode_signed_payload(cookie, SECRET, now=1_900_000_001)
    assert transaction["return_to"] == "/"

    cookie, _ = new_authorization_transaction(
        config,
        return_to="/\\evil.example",
        now=1_900_000_000,
    )
    assert decode_signed_payload(cookie, SECRET, now=1_900_000_001)["return_to"] == "/"


def test_token_exchange_prefers_client_secret_basic(monkeypatch):
    captured = {}

    def fake_request(url, *, method="GET", data=None, extra_headers=None, timeout=10.0):
        captured.update({
            "url": url,
            "method": method,
            "data": data,
            "headers": extra_headers or {},
        })
        return {"id_token": "token"}

    monkeypatch.setattr(oidc, "_json_request", fake_request)
    config = _config(client_secret="super-secret")
    payload = exchange_code(
        config,
        {
            "token_endpoint": "https://idp.example.test/token",
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
        },
        code="abc",
        verifier="verifier",
    )
    assert payload["id_token"] == "token"
    assert captured["method"] == "POST"
    assert captured["headers"]["Authorization"].startswith("Basic ")
    assert "client_secret" not in captured["data"]


def test_oidc_session_rejects_different_issuer():
    config = _config()
    now = int(time.time())
    cookie, _ = session_from_claims(
        config,
        {
            "iss": config.issuer,
            "sub": "alice@example.com",
            "exp": now + 600,
            "groups": ["SOC-T1"],
        },
        now=now,
    )
    with pytest.raises(PermissionError, match="issuer"):
        authenticate(
            {"cookie": f"{config.session_cookie}={cookie}"},
            AuthConfig(
                mode="oidc",
                oidc_session_secret=SECRET,
                oidc_session_cookie=config.session_cookie,
                oidc_issuer="https://other-idp.example.test",
            ),
        )


def test_signed_session_detects_tamper_and_expiry():
    valid = encode_signed_payload(
        {"sub": "alice", "role": "analyst", "exp": 2_000_000_000},
        SECRET,
    )
    assert decode_signed_payload(valid, SECRET, now=1_900_000_000)["sub"] == "alice"

    encoded, signature = valid.split(".", 1)
    tampered = encoded[:-1] + ("A" if encoded[-1] != "A" else "B") + "." + signature
    with pytest.raises(PermissionError, match="signature"):
        decode_signed_payload(tampered, SECRET, now=1_900_000_000)

    expired = encode_signed_payload(
        {"sub": "alice", "role": "analyst", "exp": 10},
        SECRET,
    )
    with pytest.raises(PermissionError, match="expired"):
        decode_signed_payload(expired, SECRET, now=11)


def test_authorization_transaction_has_pkce_s256_and_signed_state():
    config = _config()
    cookie, challenge = new_authorization_transaction(
        config,
        return_to="/command",
        now=1_900_000_000,
    )
    transaction = decode_signed_payload(cookie, SECRET, now=1_900_000_001)
    assert transaction["return_to"] == "/command"
    assert transaction["state"]
    assert transaction["nonce"]
    assert transaction["verifier"]
    assert len(challenge) >= 40


def test_verify_id_token_checks_signature_issuer_audience_and_nonce(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    now = int(time.time())
    config = _config()
    token = jwt.encode(
        {
            "iss": config.issuer,
            "sub": "alice@example.com",
            "aud": config.client_id,
            "iat": now,
            "exp": now + 600,
            "nonce": "nonce-123",
            "groups": ["SOC-T2"],
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    class SigningKey:
        key = public_key

    class FakeJWKClient:
        def __init__(self, uri, cache_keys=True):
            assert uri == "https://idp.example.test/jwks"
            assert cache_keys is True

        def get_signing_key_from_jwt(self, supplied):
            assert supplied == token
            return SigningKey()

    monkeypatch.setattr(jwt, "PyJWKClient", FakeJWKClient)
    claims = verify_id_token(
        config,
        {"jwks_uri": "https://idp.example.test/jwks"},
        token,
        nonce="nonce-123",
    )
    assert claims["sub"] == "alice@example.com"

    with pytest.raises(PermissionError, match="nonce"):
        verify_id_token(
            config,
            {"jwks_uri": "https://idp.example.test/jwks"},
            token,
            nonce="wrong",
        )


def test_oidc_session_authenticates_to_socmind_principal():
    config = _config()
    now = int(time.time())
    cookie, payload = session_from_claims(
        config,
        {
            "iss": config.issuer,
            "sub": "alice@example.com",
            "exp": now + 600,
            "groups": ["SOC-T2"],
        },
        now=now,
    )
    principal = authenticate(
        {"cookie": f"{config.session_cookie}={cookie}"},
        AuthConfig(
            mode="oidc",
            oidc_session_secret=SECRET,
            oidc_session_cookie=config.session_cookie,
        ),
    )
    assert payload["role"] == "senior-analyst"
    assert principal.subject == "alice@example.com"
    assert principal.role == "senior-analyst"
    assert principal.source == "oidc"


def test_web_oidc_login_callback_and_logout(monkeypatch, tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(
        '{"timestamp":"2026-09-29T00:00:00Z","source":"test","event_id":"1","host":"h1"}\n',
        encoding="utf-8",
    )
    discovery = {
        "issuer": "http://localhost:8080",
        "authorization_endpoint": "http://localhost:8080/authorize",
        "token_endpoint": "http://localhost:8080/token",
        "jwks_uri": "http://localhost:8080/jwks",
    }

    monkeypatch.setattr(webapp, "fetch_discovery", lambda config: discovery)
    monkeypatch.setattr(
        webapp,
        "exchange_code",
        lambda config, doc, *, code, verifier: {"id_token": "signed-id-token"},
    )
    monkeypatch.setattr(
        webapp,
        "verify_id_token",
        lambda config, doc, token, *, nonce: {
            "iss": config.issuer,
            "sub": "lead@example.com",
            "exp": int(time.time()) + 600,
            "groups": ["SOC-Leads"],
            "nonce": nonce,
        },
    )

    app = webapp.create_app(
        events,
        auth_mode="oidc",
        oidc_issuer="http://localhost:8080",
        oidc_client_id="socmind-client",
        oidc_redirect_uri="http://localhost/auth/callback",
        oidc_session_secret=SECRET,
        oidc_role_map={"SOC-Leads": "lead"},
        oidc_allow_insecure_http=True,
    )
    client = TestClient(app)

    root = client.get("/", follow_redirects=False)
    assert root.status_code == 302
    assert root.headers["location"].startswith("/auth/login")

    login = client.get("/auth/login?return_to=/", follow_redirects=False)
    assert login.status_code == 302
    target = urlparse(login.headers["location"])
    query = parse_qs(target.query)
    assert target.path == "/authorize"
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["openid profile email"]

    transaction_cookie = client.cookies.get("socmind_oidc_transaction")
    transaction = decode_signed_payload(transaction_cookie, SECRET)
    callback = client.get(
        f"/auth/callback?code=abc123&state={transaction['state']}",
        follow_redirects=False,
    )
    assert callback.status_code == 303

    me = client.get("/api/me")
    assert me.status_code == 200
    assert me.json() == {
        "subject": "lead@example.com",
        "role": "lead",
        "source": "oidc",
    }

    logout = client.post("/auth/logout", headers={"Origin": "http://localhost"}, follow_redirects=False)
    assert logout.status_code == 303
    assert client.get("/api/me").status_code == 401


def test_cookie_mutations_require_configured_origin(tmp_path):
    app = webapp.create_app(
        "examples/attack_chain.jsonl", auth_mode="oidc",
        oidc_issuer="https://idp.example.test", oidc_client_id="client",
        oidc_redirect_uri="https://socmind.example.test/auth/callback",
        oidc_session_secret=SECRET,
    )
    client = TestClient(app, base_url="https://socmind.example.test")
    cookie, _ = session_from_claims(_config(), {
        "iss": "https://idp.example.test", "sub": "alice", "groups": ["SOC-T1"],
        "exp": int(time.time()) + 600,
    })
    client.cookies.set("socmind_oidc_session", cookie)
    for origin in (None, "https://evil.example.test", "null"):
        headers = {} if origin is None else {"Origin": origin}
        assert client.post("/api/cases/test/acknowledge", headers=headers).status_code == 403
    # Passes CSRF and authentication; no case store is configured in this fixture.
    assert client.post("/api/cases/test/acknowledge", headers={
        "Origin": "https://socmind.example.test"}).status_code == 409


def test_oidc_rejects_endpoint_redirects():
    from urllib.request import Request
    with pytest.raises(ValueError, match="redirects"):
        oidc._NoRedirect().redirect_request(Request("https://idp.example.test"),
            None, 302, "Found", {}, "http://evil.example.test")


def test_client_basic_encodes_reserved_characters(monkeypatch):
    import base64
    captured = {}
    def request(url, **kwargs):
        captured.update(kwargs)
        return {"id_token": "token"}
    monkeypatch.setattr(oidc, "_json_request", request)
    exchange_code(_config(client_id="id:with space", client_secret="s+&:"),
        {"token_endpoint": "https://idp.example.test/token"}, code="code", verifier="v")
    encoded = captured["extra_headers"]["Authorization"].split()[1]
    assert base64.b64decode(encoded).decode() == "id%3Awith+space:s%2B%26%3A"


@pytest.mark.parametrize("invalid", ["issuer", "audience", "expiry", "signature", "nonce"])
def test_real_jwks_validation_rejects_invalid_tokens(monkeypatch, invalid):
    import json
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    key.update({"kid": "key-1", "use": "sig", "alg": "RS256"})
    requested = []
    def request(uri):
        requested.append(uri)
        return {"keys": [key]}
    monkeypatch.setattr(oidc, "_json_request", request)
    now = int(time.time())
    claims = {"iss": _config().issuer, "sub": "alice", "aud": _config().client_id,
              "iat": now - 60, "exp": now + 600, "nonce": "nonce"}
    if invalid == "issuer": claims["iss"] = "https://other.example"
    if invalid == "audience": claims["aud"] = "other-client"
    if invalid == "expiry": claims["exp"] = now - 1
    if invalid == "nonce": claims["nonce"] = "other"
    if invalid == "signature": private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "key-1"})
    with pytest.raises(PermissionError):
        verify_id_token(_config(), {"jwks_uri": "https://idp.example.test/jwks"}, token, nonce="nonce")
    assert requested == ["https://idp.example.test/jwks"]
