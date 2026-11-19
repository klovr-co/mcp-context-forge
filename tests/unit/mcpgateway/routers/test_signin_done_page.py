# -*- coding: utf-8 -*-
"""OAUTH_SIGNIN_DONE_URL: after a sign-in started from another app, a plain page links back to it."""

# Standard
import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

# Third-Party
from fastapi import Request
from fastapi.responses import HTMLResponse
import pytest
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.db import Gateway
from mcpgateway.routers.oauth_router import _signin_done_response, _signin_done_url, oauth_callback

DONE = "https://app.example.org/connectors"


@pytest.mark.parametrize("value", ["", "   ", "app.example.org/connectors", "javascript:alert(1)", "ftp://x.org/", "https://"])
def test_unset_or_not_http_means_no_done_page(monkeypatch, value):
    monkeypatch.setenv("OAUTH_SIGNIN_DONE_URL", value)
    assert _signin_done_url() is None


def test_http_url_counts(monkeypatch):
    monkeypatch.setenv("OAUTH_SIGNIN_DONE_URL", f"  {DONE} ")
    assert _signin_done_url() == DONE


def test_page_escapes_and_has_no_script():
    body = _signin_done_response('<img src=x onerror="1">', 'https://a.org/?q="x"').body.decode()
    assert "<script" not in body
    assert "<img src=x" not in body and "&lt;img" in body
    assert 'href="https://a.org/?q=&quot;x&quot;"' in body
    assert "Go back to Hover Workspace" in body


def _callback_inputs():
    state = base64.urlsafe_b64encode(json.dumps({"gateway_id": "gateway123", "app_user_email": "alice@example.com", "nonce": "n"}).encode() + b"x" * 32).decode()
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.scheme = "https"
    request.url.netloc = "gateway.example.com"
    request.scope = {"root_path": ""}
    request.state = SimpleNamespace(token_teams=["team-1"])
    request.cookies = {}
    request.query_params = {}
    gateway = Mock(spec=Gateway)
    gateway.id = "gateway123"
    gateway.name = "Slack"
    gateway.url = "https://mcp.example.com"
    gateway.visibility = "public"
    gateway.owner_email = None
    gateway.team_id = None
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
    result = {"user_id": "u1", "expires_at": "2026-01-01T00:00:00", "token_aud": None, "state_data": {"app_user_email": "alice@example.com", "team_id": None}}
    return state, request, db, result


async def _run_callback():
    state, request, db, result = _callback_inputs()
    with patch("mcpgateway.routers.oauth_router.OAuthManager") as manager_class, patch("mcpgateway.routers.oauth_router.TokenStorageService"):
        manager = Mock()
        manager.resolve_gateway_id_from_state = AsyncMock(return_value="gateway123")
        manager.complete_authorization_code_flow = AsyncMock(return_value=result)
        manager_class.return_value = manager
        return await oauth_callback(code="code", state=state, request=request, db=db)


@pytest.mark.asyncio
async def test_callback_shows_the_done_page_when_set(monkeypatch):
    monkeypatch.setenv("OAUTH_SIGNIN_DONE_URL", DONE)
    response = await _run_callback()
    assert isinstance(response, HTMLResponse)
    body = response.body.decode()
    assert "You're signed in to Slack." in body
    assert f'href="{DONE}"' in body
    assert "Fetch Tools" not in body


@pytest.mark.asyncio
async def test_callback_keeps_the_admin_page_when_unset(monkeypatch):
    monkeypatch.delenv("OAUTH_SIGNIN_DONE_URL", raising=False)
    body = (await _run_callback()).body.decode()
    assert "OAuth Authorization Successful" in body
    assert "Go back to Hover Workspace" not in body
