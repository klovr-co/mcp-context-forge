# -*- coding: utf-8 -*-
"""DELETE /oauth/tokens/{gateway_id}: a person signs out of an OAuth gateway (their own login only).

The database cases use a real session and real oauth_tokens rows, so a swallowed storage error
can't pass for a successful sign-out.
"""

# Standard
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
import uuid

# Third-Party
from fastapi import HTTPException, Request
import pytest
from sqlalchemy import select

# First-Party
from mcpgateway.db import EmailUser, Gateway, OAuthToken
from mcpgateway.routers.oauth_router import oauth_router, sign_out_of_gateway


class _AttrDict(dict):
    """``@require_permission`` needs a real dict (the runtime type); the router also reads attributes."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def _user(email):
    return _AttrDict(email=email, full_name=email, is_active=True, is_admin=False)


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
def stored(test_db):
    """A gateway with stored logins for alice and bob."""
    gateway_id = uuid.uuid4().hex
    emails = [f"alice-{gateway_id[:6]}@example.com", f"bob-{gateway_id[:6]}@example.com"]
    for email in emails:
        test_db.add(EmailUser(email=email, password_hash="x", full_name=email))  # pragma: allowlist secret
    test_db.add(
        Gateway(
            id=gateway_id,
            name=f"gw-{gateway_id[:8]}",
            slug=f"gw-{gateway_id[:8]}",
            url=f"https://mcp.example.com/{gateway_id}",
            description="synthetic",
            transport="STREAMABLEHTTP",
            capabilities={},
            enabled=True,
            reachable=True,
            auth_type="oauth",
            oauth_config={"grant_type": "authorization_code", "client_id": "c"},
            visibility="public",
        )
    )
    test_db.commit()
    for email in emails:
        test_db.add(OAuthToken(gateway_id=gateway_id, user_id=f"up-{email}", app_user_email=email, access_token="tok"))
    test_db.commit()
    alice, bob = emails
    return SimpleNamespace(gateway_id=gateway_id, alice=alice, bob=bob)


def _logins(db, gateway_id):
    return sorted(db.execute(select(OAuthToken.app_user_email).where(OAuthToken.gateway_id == gateway_id)).scalars())


def test_route_is_delete_tokens_gateway_id():
    routes = [(r.path, sorted(r.methods)) for r in oauth_router.routes if getattr(r, "endpoint", None) is sign_out_of_gateway]
    assert routes == [("/oauth/tokens/{gateway_id}", ["DELETE"])]


@pytest.mark.asyncio
async def test_signs_out_the_caller_and_leaves_others(test_db, request_, stored):
    result = await sign_out_of_gateway(stored.gateway_id, request_, current_user=_user(stored.alice), db=test_db)
    assert result == {"gateway_id": stored.gateway_id, "signed_out": True}
    assert _logins(test_db, stored.gateway_id) == [stored.bob]


@pytest.mark.asyncio
async def test_nothing_stored_answers_signed_out_false(test_db, request_, stored):
    await sign_out_of_gateway(stored.gateway_id, request_, current_user=_user(stored.alice), db=test_db)
    again = await sign_out_of_gateway(stored.gateway_id, request_, current_user=_user(stored.alice), db=test_db)
    assert again == {"gateway_id": stored.gateway_id, "signed_out": False}
    assert _logins(test_db, stored.gateway_id) == [stored.bob]


@pytest.mark.asyncio
async def test_a_failed_delete_is_500_and_the_login_stays(test_db, request_, stored):
    """The database backend swallows commit errors and answers False; the route must not report that as done."""
    real_commit = test_db.commit

    def failing_commit():
        if test_db.deleted:
            raise RuntimeError("database went away")
        real_commit()

    with patch.object(test_db, "commit", side_effect=failing_commit):
        with pytest.raises(HTTPException) as e:
            await sign_out_of_gateway(stored.gateway_id, request_, current_user=_user(stored.alice), db=test_db)
    assert e.value.status_code == 500
    assert _logins(test_db, stored.gateway_id) == sorted([stored.alice, stored.bob])


@pytest.mark.asyncio
async def test_a_failed_read_is_500(test_db, request_, stored):
    with patch("mcpgateway.routers.oauth_router._caller_login_stored", new=AsyncMock(side_effect=RuntimeError("db down"))):
        with pytest.raises(HTTPException) as e:
            await sign_out_of_gateway(stored.gateway_id, request_, current_user=_user(stored.alice), db=test_db)
    assert e.value.status_code == 500


@pytest.mark.asyncio
async def test_unknown_gateway_is_404(test_db, request_, stored):
    with pytest.raises(HTTPException) as e:
        await sign_out_of_gateway(uuid.uuid4().hex, request_, current_user=_user(stored.alice), db=test_db)
    assert e.value.status_code == 404
    assert _logins(test_db, stored.gateway_id) == sorted([stored.alice, stored.bob])


@pytest.mark.asyncio
async def test_a_gateway_the_caller_cannot_see_is_refused_and_nothing_deleted(test_db, request_, stored):
    with patch("mcpgateway.routers.oauth_router._enforce_gateway_access", new=AsyncMock(side_effect=HTTPException(status_code=403, detail="nope"))):
        with pytest.raises(HTTPException) as e:
            await sign_out_of_gateway(stored.gateway_id, request_, current_user=_user(stored.alice), db=test_db)
    assert e.value.status_code == 403
    assert _logins(test_db, stored.gateway_id) == sorted([stored.alice, stored.bob])


@pytest.mark.asyncio
async def test_someone_elses_private_gateway_is_refused_by_the_real_access_check(test_db, request_, stored):
    gw = test_db.get(Gateway, stored.gateway_id)
    gw.visibility = "private"
    gw.owner_email = stored.bob
    test_db.commit()
    with pytest.raises(HTTPException) as e:
        await sign_out_of_gateway(stored.gateway_id, request_, current_user=_user(stored.alice), db=test_db)
    assert e.value.status_code in (403, 404)
    assert _logins(test_db, stored.gateway_id) == sorted([stored.alice, stored.bob])
