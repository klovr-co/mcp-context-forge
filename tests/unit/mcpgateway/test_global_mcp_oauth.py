# -*- coding: utf-8 -*-
"""OAuth sign-in on the gateway's own /mcp address (MCP_OAUTH_AUTHORIZATION_SERVERS).

An MCP client that connects to <APP_DOMAIN>/mcp without a token gets a 401
naming /mcp's RFC 9728 metadata, finds the authorization server there, and
comes back with an access token for resource <APP_DOMAIN>/mcp. The gateway
checks the token's signature, issuer, audience and expiry and resolves the
person from the database, as for an oauth_enabled virtual server. The
gateway's own tokens keep working on /mcp.
"""

# Standard
from contextlib import asynccontextmanager
import time
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
import jwt
import pytest

# First-Party
from mcpgateway.config import Settings, settings
from mcpgateway.routers import well_known
from mcpgateway.transports import streamablehttp_transport as tr
from mcpgateway.utils import verify_credentials as vc

GATEWAY = "https://dock.example.com"
ISSUER = "https://idp.example.com"
RESOURCE = f"{GATEWAY}/mcp"
METADATA_URL = f"{GATEWAY}/.well-known/oauth-protected-resource/mcp"
JWKS_URI = f"{ISSUER}/oauth2/jwks"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "app_domain", GATEWAY)
    monkeypatch.setattr(settings, "mcp_oauth_authorization_servers", [ISSUER])
    monkeypatch.setattr(settings, "mcp_oauth_scopes", ["openid", "profile", "email", "offline_access"])
    monkeypatch.setattr(settings, "mcp_require_auth", True)
    monkeypatch.setattr(settings, "well_known_enabled", True)


@pytest.fixture
def idp(monkeypatch):
    """The IdP's discovery and keys, so verify_oauth_access_token runs for real."""
    monkeypatch.setattr(vc, "_discover_oidc_metadata", AsyncMock(return_value={"issuer": ISSUER, "jwks_uri": JWKS_URI}))
    jwks_client = MagicMock()
    jwks_client.get_signing_key_from_jwt.return_value = MagicMock(key=_KEY.public_key())
    monkeypatch.setitem(vc._oauth_jwks_client_cache, JWKS_URI, jwks_client)


@pytest.fixture
def person(monkeypatch):
    user = MagicMock(is_active=True, is_admin=False)
    get_user = MagicMock(return_value=user)
    monkeypatch.setattr("mcpgateway.auth._get_user_by_email_sync", get_user)
    monkeypatch.setattr("mcpgateway.auth._resolve_teams_from_db", AsyncMock(return_value=["team-klovr"]))
    return get_user


def _fake_get_db(db):
    @asynccontextmanager
    async def _fake():
        yield db

    return _fake


def _idp_token(**overrides) -> str:
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": RESOURCE, "sub": "user_01", "email": "Person@Example.com", "iat": now, "exp": now + 300}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, _KEY, algorithm="RS256")


async def _call(path: str, token: str | None = None) -> tuple[bool, list[dict]]:
    headers = [(b"authorization", f"Bearer {token}".encode())] if token else []
    scope = {"type": "http", "method": "POST", "path": path, "headers": headers, "scheme": "https", "server": ("localhost", 4444), "client": ("127.0.0.1", 0)}
    sent: list[dict] = []

    async def send(msg):
        sent.append(msg)

    checked = tr._oauth_checked_var.set(False)
    try:
        ok = await tr.streamable_http_auth(scope, AsyncMock(), send)
    finally:
        tr._oauth_checked_var.reset(checked)
    return ok, sent


def _www_authenticate(sent: list[dict]) -> str:
    return dict(sent[0].get("headers", [])).get(b"www-authenticate", b"").decode()


# --- 401 without a token -----------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/mcp", "/mcp/"])
async def test_no_token_401_names_mcp_metadata(configured, path):
    ok, sent = await _call(path)
    assert ok is False
    assert sent[0]["status"] == 401
    assert _www_authenticate(sent) == f'Bearer resource_metadata="{METADATA_URL}"'


@pytest.mark.asyncio
async def test_no_token_401_stays_plain_when_not_configured(configured, monkeypatch):
    monkeypatch.setattr(settings, "mcp_oauth_authorization_servers", [])
    ok, sent = await _call("/mcp")
    assert ok is False
    assert sent[0]["status"] == 401
    assert _www_authenticate(sent) == "Bearer"


# --- the metadata document ---------------------------------------------------------------


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(well_known.router)
    return TestClient(app)


def test_metadata_document_names_the_authorization_server(configured):
    response = _client().get("/.well-known/oauth-protected-resource/mcp")
    assert response.status_code == 200
    assert response.json() == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    }
    assert "max-age" in response.headers["cache-control"]


def test_root_metadata_document_is_the_same(configured):
    client = _client()
    assert client.get("/.well-known/oauth-protected-resource").json() == client.get("/.well-known/oauth-protected-resource/mcp").json()


def test_metadata_404_when_not_configured(configured, monkeypatch):
    monkeypatch.setattr(settings, "mcp_oauth_authorization_servers", [])
    client = _client()
    assert client.get("/.well-known/oauth-protected-resource/mcp").status_code == 404
    assert client.get("/.well-known/oauth-protected-resource").status_code == 404


def test_settings_take_csv_or_json_lists():
    fresh = Settings(
        mcp_oauth_authorization_servers=f"{ISSUER}, https://other.example.com",
        mcp_oauth_scopes='["openid","email"]',
        environment="development",
        _env_file=None,
    )
    assert fresh.mcp_oauth_authorization_servers == [ISSUER, "https://other.example.com"]
    assert fresh.mcp_oauth_scopes == ["openid", "email"]
    assert Settings(environment="development", _env_file=None).mcp_oauth_authorization_servers == []


# --- IdP tokens on /mcp ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_idp_token_for_mcp_is_accepted_as_the_person(configured, idp, person):
    ok, sent = await _call("/mcp", _idp_token())
    assert ok is True
    assert sent == []
    ctx = tr.user_context_var.get()
    assert ctx["email"] == "person@example.com"
    assert ctx["teams"] == ["team-klovr"]
    assert ctx["auth_method"] == "oauth_access_token"
    assert ctx["token_use"] == "session"
    person.assert_called_once_with("person@example.com")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"aud": f"{GATEWAY}/servers/abc/mcp"}, id="token-for-a-bundle"),
        pytest.param({"aud": None}, id="no-audience"),
        pytest.param({"exp": int(time.time()) - 60}, id="expired"),
        pytest.param({"exp": None}, id="no-expiry"),
        pytest.param({"nonce": "n"}, id="id-token"),
    ],
)
async def test_bad_idp_token_is_refused_with_the_challenge(configured, idp, person, overrides):
    ok, sent = await _call("/mcp", _idp_token(**overrides))
    assert ok is False
    assert sent[0]["status"] == 401
    assert _www_authenticate(sent) == f'Bearer resource_metadata="{METADATA_URL}"'
    person.assert_not_called()


@pytest.mark.asyncio
async def test_token_signed_by_another_key_is_refused(configured, idp, person):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    forged = jwt.encode({"iss": ISSUER, "aud": RESOURCE, "email": "person@example.com", "iat": now, "exp": now + 300}, other, algorithm="RS256")
    ok, sent = await _call("/mcp", forged)
    assert ok is False
    assert sent[0]["status"] == 401
    person.assert_not_called()


@pytest.mark.asyncio
async def test_foreign_issuer_is_refused(configured, idp, person, monkeypatch):
    monkeypatch.setattr(tr, "verify_credentials_cached", AsyncMock(side_effect=tr.HTTPException(status_code=401, detail="Invalid token")))
    ok, sent = await _call("/mcp", _idp_token(iss="https://evil.example.com"))
    assert ok is False
    assert sent[0]["status"] == 401
    assert _www_authenticate(sent) == f'Bearer resource_metadata="{METADATA_URL}"'
    person.assert_not_called()


@pytest.mark.asyncio
async def test_idp_token_is_not_for_mcp_when_not_configured(configured, idp, person, monkeypatch):
    monkeypatch.setattr(settings, "mcp_oauth_authorization_servers", [])
    monkeypatch.setattr(tr, "verify_credentials_cached", AsyncMock(side_effect=tr.HTTPException(status_code=401, detail="Invalid token")))
    ok, sent = await _call("/mcp", _idp_token())
    assert ok is False
    assert sent[0]["status"] == 401
    person.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("record", [None, MagicMock(is_active=False, is_admin=False)], ids=["unknown", "disabled"])
async def test_unknown_or_disabled_person_is_refused_with_the_challenge(configured, idp, person, record):
    person.return_value = record
    ok, sent = await _call("/mcp", _idp_token())
    assert ok is False
    assert sent[0]["status"] == 401
    assert _www_authenticate(sent) == f'Bearer resource_metadata="{METADATA_URL}"'


@pytest.mark.asyncio
async def test_idp_token_accepted_with_trailing_slash(configured, idp, person):
    ok, sent = await _call("/mcp/", _idp_token())
    assert ok is True
    assert tr.user_context_var.get()["email"] == "person@example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/mcp/sse", "/mcp/message", "/servers/abc/mcp"])
async def test_idp_token_for_mcp_only_opens_mcp(configured, idp, person, monkeypatch, path):
    """Other MCP paths never reach the /mcp branch: the usual checks refuse the token."""
    monkeypatch.setattr(tr, "_check_server_oauth_enforcement", AsyncMock(return_value=None))
    db = MagicMock()
    db.execute.return_value.scalar_one_or_none.return_value = None
    monkeypatch.setattr(tr, "get_db", _fake_get_db(db))
    fallback = AsyncMock(side_effect=tr.HTTPException(status_code=401, detail="Invalid token"))
    monkeypatch.setattr(tr, "verify_credentials_cached", fallback)
    ok, sent = await _call(path, _idp_token())
    assert ok is False
    assert sent[0]["status"] == 401
    fallback.assert_awaited_once()
    person.assert_not_called()


# --- the gateway's own tokens ------------------------------------------------------------


@pytest.mark.asyncio
async def test_gateway_token_still_works_on_mcp(configured, monkeypatch):
    """The shared static token (a gateway-issued JWT) takes the usual path, untouched."""
    own = jwt.encode({"iss": settings.jwt_issuer, "sub": "service@example.com"}, "x" * 32, algorithm="HS256")
    verify = AsyncMock(return_value={"sub": "service@example.com", "teams": ["team1"], "user": {"is_admin": False}})
    monkeypatch.setattr(tr, "verify_credentials_cached", verify)
    cache = MagicMock()
    cache.get_team_membership_valid_sync.return_value = True
    with patch("mcpgateway.cache.auth_cache.get_auth_cache", return_value=cache):
        ok, sent = await _call("/mcp", own)
    assert ok is True
    assert sent == []
    verify.assert_awaited_once()
    assert tr.user_context_var.get()["email"] == "service@example.com"


@pytest.mark.asyncio
async def test_bad_gateway_token_is_refused_with_the_challenge(configured, monkeypatch):
    monkeypatch.setattr(tr, "verify_credentials_cached", AsyncMock(side_effect=tr.HTTPException(status_code=401, detail="Invalid token")))
    ok, sent = await _call("/mcp", "not-a-jwt")
    assert ok is False
    assert sent[0]["status"] == 401
    assert _www_authenticate(sent) == f'Bearer resource_metadata="{METADATA_URL}"'


@pytest.mark.asyncio
async def test_virtual_server_401_is_unchanged(configured, monkeypatch):
    monkeypatch.setattr(tr, "_check_server_oauth_enforcement", AsyncMock(return_value=None))
    ok, sent = await _call("/servers/abc/mcp")
    assert ok is False
    assert _www_authenticate(sent) == "Bearer"
