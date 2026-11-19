# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/services/test_oauth_account.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Whose account a caller's saved OAuth sign-in is, asked of a stand-in authorization
server that publishes its metadata and a UserInfo endpoint.
"""

# Standard
from contextlib import asynccontextmanager
import socket
from types import SimpleNamespace
from unittest.mock import Mock, patch

# Third-Party
from fastapi import Request
import httpx
import pytest
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.db import Gateway
from mcpgateway.services import oauth_account
from mcpgateway.services.oauth_account import signed_in_account
from mcpgateway.services.token_backends.base import ValidationToken

ISSUER = "https://as.example.com/auth/v1"
USERINFO = "https://as.example.com/auth/v1/oauth/userinfo"
PUBLIC_TEST_IP = "93.184.216.34"
SIGNED_IN = "2026-11-19T10:00:00+00:00"


class StandInServer:
    """An authorization server: metadata at the RFC 8414 address, and a UserInfo endpoint that
    names a token's account, with its email only for a sign-in that asked for ``email``."""

    def __init__(self, userinfo_endpoint=USERINFO, userinfo_status=200):
        self.userinfo_endpoint = userinfo_endpoint
        self.userinfo_status = userinfo_status
        self.accounts = {"token-email": {"sub": "u-1", "email": "maxine@example.com", "email_verified": True}, "token-openid": {"sub": "u-2"}}
        self.requests = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        host = request.headers.get("host")
        self.requests.append((host, request.url.path, request.headers.get("authorization")))
        if host != "as.example.com":
            return httpx.Response(200, json={"sub": "someone-else"})
        if request.url.path == "/.well-known/oauth-authorization-server/auth/v1":
            metadata = {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/oauth/authorize", "token_endpoint": f"{ISSUER}/oauth/token"}
            if self.userinfo_endpoint:
                metadata["userinfo_endpoint"] = self.userinfo_endpoint
            return httpx.Response(200, json=metadata)
        if request.url.path == "/auth/v1/oauth/userinfo":
            if self.userinfo_status != 200:
                return httpx.Response(self.userinfo_status, json={"error": "nope"})
            token = (request.headers.get("authorization") or "").removeprefix("Bearer ")
            if token not in self.accounts:
                return httpx.Response(401, json={"error": "invalid_token"})
            return httpx.Response(200, json=self.accounts[token])
        return httpx.Response(404)

    def tokens_sent(self):
        return [(host, path) for host, path, auth in self.requests if auth]


class Storage:
    """The caller's saved sign-in, as the token storage reads it."""

    def __init__(self, token="token-email", status="valid", updated_at=SIGNED_IN, later_updated_at=None):
        self.token = ValidationToken(status, token)
        self.updated_at = updated_at
        self.later_updated_at = later_updated_at
        self.reads = 0

    async def read_validation_token(self, gateway_id, app_user_email):
        return self.token

    async def get_token_info(self, gateway_id, app_user_email):
        self.reads += 1
        return {"status": self.token.status, "updated_at": self.later_updated_at or self.updated_at, "scopes": ["openid"]}


@pytest.fixture(autouse=True)
def fresh_answers():
    """No answer or metadata kept from another test.

    Yields:
        None
    """
    # First-Party
    from mcpgateway.services.dcr_service import _metadata_cache

    oauth_account._answers.clear()
    _metadata_cache.clear()
    yield
    oauth_account._answers.clear()
    _metadata_cache.clear()


@pytest.fixture(autouse=True)
def stub_dns(monkeypatch):
    """Every test hostname resolves to one public address, so connection pinning can run."""

    def _fake_getaddrinfo(_host, port, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_TEST_IP, port or 443))]

    monkeypatch.setattr("mcpgateway.common.validators.socket.getaddrinfo", _fake_getaddrinfo)


@pytest.fixture
def server():
    """The stand-in authorization server, reached by every outbound client.

    Yields:
        StandInServer: The server, with the requests it got.
    """
    stand_in = StandInServer()

    @asynccontextmanager
    async def client(*_args, **_kwargs):
        async with httpx.AsyncClient(transport=httpx.MockTransport(stand_in.handle)) as c:
            yield c

    with patch("mcpgateway.services.dcr_service.get_isolated_http_client", client), patch("mcpgateway.services.oauth_account.get_isolated_http_client", client):
        yield stand_in


async def ask(storage, oauth_config=None):
    return await signed_in_account(storage, "gw-1", {"issuer": ISSUER} if oauth_config is None else oauth_config, "maxine@hover.test", storage.updated_at)


@pytest.mark.asyncio
async def test_names_the_account_with_its_email(server):
    assert await ask(Storage("token-email")) == {"sub": "u-1", "email": "maxine@example.com"}
    assert server.tokens_sent() == [("as.example.com", "/auth/v1/oauth/userinfo")]


@pytest.mark.asyncio
async def test_a_sign_in_without_the_email_scope_names_only_its_sub(server):
    assert await ask(Storage("token-openid")) == {"sub": "u-2"}


@pytest.mark.asyncio
async def test_no_userinfo_endpoint_names_nobody_and_sends_no_token(server):
    server.userinfo_endpoint = None
    assert await ask(Storage()) is None
    assert server.tokens_sent() == []


@pytest.mark.asyncio
async def test_the_token_never_goes_to_another_origin(server):
    server.userinfo_endpoint = "https://elsewhere.example.net/userinfo"
    assert await ask(Storage()) is None
    assert server.tokens_sent() == []
    assert all(host == "as.example.com" for host, _path, _auth in server.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["expired", "invalid", "unbound"])
async def test_a_token_that_is_not_valid_now_is_not_sent(server, status):
    assert await ask(Storage(status=status)) is None
    assert server.requests == []


@pytest.mark.asyncio
async def test_a_gateway_without_an_issuer_asks_nobody(server):
    assert await ask(Storage(), oauth_config={"grant_type": "authorization_code"}) is None
    assert server.requests == []


@pytest.mark.asyncio
async def test_a_refused_token_names_nobody(server):
    assert await ask(Storage("token-unknown")) is None
    assert server.tokens_sent() == [("as.example.com", "/auth/v1/oauth/userinfo")]


@pytest.mark.asyncio
async def test_an_answer_about_a_sign_in_replaced_meanwhile_is_dropped(server):
    storage = Storage("token-email", later_updated_at="2026-11-19T10:05:00+00:00")
    assert await ask(storage) is None
    assert oauth_account._answers == {}


@pytest.mark.asyncio
async def test_one_question_per_saved_sign_in(server):
    storage = Storage("token-email")
    assert await ask(storage) == {"sub": "u-1", "email": "maxine@example.com"}
    assert await ask(storage) == {"sub": "u-1", "email": "maxine@example.com"}
    assert len(server.tokens_sent()) == 1

    renewed = Storage("token-openid", updated_at="2026-11-19T11:00:00+00:00")
    assert await ask(renewed) == {"sub": "u-2"}
    assert len(server.tokens_sent()) == 2


@pytest.mark.asyncio
async def test_a_failed_question_is_asked_again_after_a_minute(server, monkeypatch):
    server.userinfo_status = 503
    storage = Storage("token-email")
    assert await ask(storage) is None
    assert await ask(storage) is None
    assert len(server.tokens_sent()) == 1

    server.userinfo_status = 200
    now = oauth_account.monotonic()
    monkeypatch.setattr(oauth_account, "monotonic", lambda: now + 61)
    assert await ask(storage) == {"sub": "u-1", "email": "maxine@example.com"}


class _User(dict):
    """The caller as the route gets it: a dict (``@require_permission`` checks that) that some helpers read by attribute."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class TestStatusRoute:
    """GET /oauth/status/{gateway_id}?include_account=true"""

    @pytest.fixture
    def gateway(self):
        gateway = Mock(spec=Gateway)
        gateway.id = "gw-1"
        gateway.name = "Stand-in"
        gateway.url = "https://mcp.example.com"
        gateway.visibility = "public"
        gateway.owner_email = None
        gateway.team_id = None
        gateway.oauth_config = {"grant_type": "authorization_code", "client_id": "c", "issuer": ISSUER, "scopes": ["openid", "email"]}
        return gateway

    @pytest.fixture
    def request_(self):
        request = Mock(spec=Request)
        request.url = Mock()
        request.url.scheme = "https"
        request.url.netloc = "gateway.example.com"
        request.scope = {"root_path": ""}
        request.state = SimpleNamespace(token_teams=["team-1"])
        return request

    async def status(self, gateway, request, storage, **query):
        # First-Party
        from mcpgateway.routers.oauth_router import get_oauth_status

        db = Mock(spec=Session)
        db.execute.return_value.scalar_one_or_none.return_value = gateway
        user = _User(email="maxine@hover.test", is_admin=False, is_active=True)
        with patch("mcpgateway.routers.oauth_router.TokenStorageService", return_value=storage):
            return await get_oauth_status("gw-1", request, current_user=user, db=db, **query)

    @pytest.mark.asyncio
    async def test_reports_the_account_when_asked(self, server, gateway, request_):
        result = await self.status(gateway, request_, Storage("token-email"), include_account=True)
        assert result["user_token_status"]["account"] == {"sub": "u-1", "email": "maxine@example.com"}
        assert result["user_token_status"]["updated_at"] == SIGNED_IN
        assert "token-email" not in repr(result)

    @pytest.mark.asyncio
    async def test_unchanged_when_not_asked(self, server, gateway, request_):
        result = await self.status(gateway, request_, Storage("token-email"))
        assert "account" not in result["user_token_status"]
        assert server.requests == []

    @pytest.mark.asyncio
    async def test_no_account_for_a_sign_in_that_is_not_held(self, server, gateway, request_):
        result = await self.status(gateway, request_, Storage("token-email", status="expired"), include_account=True)
        assert result["user_token_status"]["authorized"] is False
        assert "account" not in result["user_token_status"]
        assert server.requests == []

    @pytest.mark.asyncio
    async def test_a_server_that_cannot_be_reached_leaves_the_status_as_it_was(self, server, gateway, request_):
        server.userinfo_status = 500
        result = await self.status(gateway, request_, Storage("token-email"), include_account=True)
        assert result["user_token_status"]["status"] == "valid"
        assert "account" not in result["user_token_status"]
