# -*- coding: utf-8 -*-
"""DELETE /oauth/tokens/{gateway_id}: a person signs out of an OAuth gateway (their own login only)."""

# Standard
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

# Third-Party
from fastapi import HTTPException, Request
import pytest
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.db import Gateway
from mcpgateway.routers.oauth_router import oauth_router, sign_out_of_gateway


@pytest.fixture
def db():
    return Mock(spec=Session)


@pytest.fixture
def request_():
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.scheme = "https"
    request.url.netloc = "gateway.example.com"
    request.scope = {"root_path": ""}
    request.state = SimpleNamespace(token_teams=["team-1"])
    return request


@pytest.fixture
def gateway():
    gw = Mock(spec=Gateway)
    gw.id = "gateway123"
    gw.visibility = "public"
    gw.owner_email = None
    gw.team_id = None
    gw.oauth_config = {"grant_type": "authorization_code", "client_id": "c"}
    return gw


class _AttrDict(dict):
    """``@require_permission`` needs a real dict (the runtime type); the router also reads attributes."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


@pytest.fixture
def user():
    return _AttrDict(email="alice@example.com", full_name="Alice", is_active=True, is_admin=False)


def storage(revoked):
    cls = Mock()
    cls.return_value.revoke_user_tokens = AsyncMock(return_value=revoked)
    return cls


def test_route_is_delete_tokens_gateway_id():
    routes = [(r.path, sorted(r.methods)) for r in oauth_router.routes if getattr(r, "endpoint", None) is sign_out_of_gateway]
    assert routes == [("/oauth/tokens/{gateway_id}", ["DELETE"])]


@pytest.mark.asyncio
async def test_deletes_only_the_callers_own_login(db, request_, gateway, user):
    db.execute.return_value.scalar_one_or_none.return_value = gateway
    cls = storage(True)
    with patch("mcpgateway.routers.oauth_router.TokenStorageService", cls):
        result = await sign_out_of_gateway("gateway123", request_, current_user=user, db=db)
    assert result == {"gateway_id": "gateway123", "signed_out": True}
    cls.return_value.revoke_user_tokens.assert_awaited_once_with("gateway123", "alice@example.com")


@pytest.mark.asyncio
async def test_no_stored_login_answers_signed_out_false(db, request_, gateway, user):
    db.execute.return_value.scalar_one_or_none.return_value = gateway
    with patch("mcpgateway.routers.oauth_router.TokenStorageService", storage(False)):
        result = await sign_out_of_gateway("gateway123", request_, current_user=user, db=db)
    assert result == {"gateway_id": "gateway123", "signed_out": False}


@pytest.mark.asyncio
async def test_unknown_gateway_is_404(db, request_, user):
    db.execute.return_value.scalar_one_or_none.return_value = None
    cls = storage(True)
    with patch("mcpgateway.routers.oauth_router.TokenStorageService", cls):
        with pytest.raises(HTTPException) as e:
            await sign_out_of_gateway("nope", request_, current_user=user, db=db)
    assert e.value.status_code == 404
    cls.return_value.revoke_user_tokens.assert_not_called()


@pytest.mark.asyncio
async def test_a_gateway_the_caller_cannot_see_is_refused_and_nothing_deleted(db, request_, gateway, user):
    db.execute.return_value.scalar_one_or_none.return_value = gateway
    cls = storage(True)
    with patch("mcpgateway.routers.oauth_router.TokenStorageService", cls), patch(
        "mcpgateway.routers.oauth_router._enforce_gateway_access", new=AsyncMock(side_effect=HTTPException(status_code=403, detail="nope"))
    ):
        with pytest.raises(HTTPException) as e:
            await sign_out_of_gateway("gateway123", request_, current_user=user, db=db)
    assert e.value.status_code == 403
    cls.return_value.revoke_user_tokens.assert_not_called()


@pytest.mark.asyncio
async def test_storage_failure_is_500(db, request_, gateway, user):
    db.execute.return_value.scalar_one_or_none.return_value = gateway
    cls = Mock()
    cls.return_value.revoke_user_tokens = AsyncMock(side_effect=RuntimeError("db down"))
    with patch("mcpgateway.routers.oauth_router.TokenStorageService", cls):
        with pytest.raises(HTTPException) as e:
            await sign_out_of_gateway("gateway123", request_, current_user=user, db=db)
    assert e.value.status_code == 500
