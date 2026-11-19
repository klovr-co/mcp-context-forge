# -*- coding: utf-8 -*-
"""A sign-in started by an app (return_to_app) always goes back to OAUTH_SIGNIN_DONE_URL with a result
code, never to a page. Sign-ins started from the admin pages keep the admin page."""

# Standard
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlparse

# Third-Party
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
import pytest
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.db import Gateway
from mcpgateway.routers.oauth_router import _back_to_app, _signin_done_url, oauth_callback
from mcpgateway.services.oauth_manager import OAuthError, OAuthManager

DONE = "https://app.example.org/connectors/signed-in"
APP_STATE = "app.abcdefghijklmnop"
ADMIN_STATE = "abcdefghijklmnop"


@pytest.mark.parametrize("value", ["", "   ", "app.example.org/x", "javascript:alert(1)", "ftp://x.org/", "https://"])
def test_unset_or_not_http_means_no_way_back(monkeypatch, value):
    monkeypatch.setenv("OAUTH_SIGNIN_DONE_URL", value)
    assert _signin_done_url() is None


def test_back_to_app_carries_only_codes():
    loc = _back_to_app(DONE, "failed", "something the provider said", "g1").headers["location"]
    assert parse_qs(urlparse(loc).query) == {"result": ["failed"], "reason": ["unknown"], "gateway": ["g1"]}
    assert _back_to_app(DONE, "ok").headers["location"] == f"{DONE}?result=ok"


def _request():
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.scheme = "https"
    request.url.netloc = "gateway.example.com"
    request.scope = {"root_path": ""}
    request.state = SimpleNamespace(token_teams=["team-1"])
    request.cookies = {}
    request.query_params = {}
    return request


def _db():
    gateway = Mock(spec=Gateway)
    gateway.id = "gateway123"
    gateway.name = "google-gmail"
    gateway.url = "https://mcp.example.com"
    gateway.visibility = "public"
    gateway.owner_email = None
    gateway.team_id = None
    gateway.tools = []
    gateway.oauth_config = {
        "grant_type": "authorization_code",
        "client_id": "c",
        "client_secret": "s",  # pragma: allowlist secret
        "authorization_url": "https://oauth.example.com/authorize",
        "token_url": "https://oauth.example.com/token",
        "redirect_uri": "https://gateway.example.com/oauth/callback",
        "scopes": ["read"],
    }
    db = Mock(spec=Session)
    db.execute.return_value.scalar_one_or_none.return_value = gateway
    return db


async def _callback(state, *, code="code", error=None, gateway_id="gateway123", complete=None):
    result = {"user_id": "u1", "expires_at": None, "token_aud": None, "token_response": {"access_token": "t"}, "state_data": {"app_user_email": "alice@example.com", "team_id": None}}
    with patch("mcpgateway.routers.oauth_router.OAuthManager") as manager_class, patch("mcpgateway.routers.oauth_router.TokenStorageService"):
        manager = Mock()
        manager.resolve_gateway_id_from_state = AsyncMock(return_value=gateway_id)
        manager.validate_authorization_response_issuer = AsyncMock(return_value=None)
        manager.complete_authorization_code_flow = complete or AsyncMock(return_value=result)
        manager_class.return_value = manager
        return await oauth_callback(code=code, state=state, error=error, request=_request(), db=_db())


def _query(response):
    assert isinstance(response, RedirectResponse) and response.status_code == 302
    loc = response.headers["location"]
    assert loc.startswith(DONE + "?")
    return {k: v[0] for k, v in parse_qs(urlparse(loc).query).items()}


@pytest.fixture
def done(monkeypatch):
    monkeypatch.setenv("OAUTH_SIGNIN_DONE_URL", DONE)


@pytest.mark.asyncio
async def test_success_goes_back_with_ok_and_the_gateway(done):
    assert _query(await _callback(APP_STATE)) == {"result": "ok", "gateway": "gateway123"}


@pytest.mark.asyncio
async def test_cancel_at_the_provider_is_denied(done):
    assert _query(await _callback(APP_STATE, code=None, error="access_denied")) == {"result": "failed", "reason": "denied", "gateway": "gateway123"}


@pytest.mark.asyncio
async def test_other_provider_errors_are_provider_error(done):
    assert _query(await _callback(APP_STATE, code=None, error="server_error"))["reason"] == "provider_error"


@pytest.mark.asyncio
async def test_missing_code_is_provider_error(done):
    assert _query(await _callback(APP_STATE, code=None))["reason"] == "provider_error"


@pytest.mark.asyncio
async def test_unknown_state_is_expired_without_a_gateway(done):
    assert _query(await _callback(APP_STATE, gateway_id=None)) == {"result": "failed", "reason": "expired"}


@pytest.mark.asyncio
async def test_token_exchange_failure_is_provider_error(done):
    q = _query(await _callback(APP_STATE, complete=AsyncMock(side_effect=OAuthError("bad code"))))
    assert q["result"] == "failed" and q["reason"] == "provider_error"


@pytest.mark.asyncio
async def test_unexpected_failure_is_unknown(done):
    q = _query(await _callback(APP_STATE, complete=AsyncMock(side_effect=RuntimeError("boom"))))
    assert q["result"] == "failed" and q["reason"] == "unknown"


@pytest.mark.asyncio
async def test_admin_sign_in_keeps_the_admin_page(done):
    response = await _callback(ADMIN_STATE)
    assert isinstance(response, HTMLResponse) and "OAuth Authorization Successful" in response.body.decode()


@pytest.mark.asyncio
async def test_app_sign_in_without_the_setting_keeps_the_admin_page(monkeypatch):
    monkeypatch.delenv("OAUTH_SIGNIN_DONE_URL", raising=False)
    response = await _callback(APP_STATE)
    assert isinstance(response, HTMLResponse) and "OAuth Authorization Successful" in response.body.decode()


@pytest.mark.asyncio
async def test_return_to_app_prefixes_the_state_and_popup_wins():
    manager = OAuthManager(token_storage=None)
    creds = {"client_id": "c", "authorization_url": "https://oauth.example.com/authorize", "redirect_uri": "https://gw/oauth/callback", "scopes": ["read"]}
    assert (await manager.initiate_authorization_code_flow("g1", creds, app_user_email="a@x.org", return_to_app=True))["state"].startswith("app.")
    assert (await manager.initiate_authorization_code_flow("g1", creds, app_user_email="a@x.org", popup=True, return_to_app=True))["state"].startswith("popup.")
    assert not (await manager.initiate_authorization_code_flow("g1", creds, app_user_email="a@x.org"))["state"].startswith("app.")
