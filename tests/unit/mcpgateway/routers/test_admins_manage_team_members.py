# -*- coding: utf-8 -*-
"""Platform admins manage any team's members, as they may already update or delete any team."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi import HTTPException, status
import pytest
from sqlalchemy.orm import Session

from mcpgateway.db import EmailTeamMember, EmailUser
from mcpgateway.schemas import TeamMemberAddRequest, TeamMemberUpdateRequest
from mcpgateway.services.team_management_service import TeamManagementService

from tests.utils.rbac_mocks import patch_rbac_decorators, restore_rbac_decorators


@pytest.fixture(autouse=True)
def rbac_mocks():
    originals = patch_rbac_decorators()
    yield
    restore_rbac_decorators(originals)


@pytest.fixture
def db():
    return MagicMock(spec=Session)


@pytest.fixture
def user():
    return {"email": "admin@example.com", "full_name": "Admin", "is_admin": False, "db": None, "token_teams": None}


@pytest.fixture
def member():
    m = MagicMock(spec=EmailTeamMember)
    m.id, m.team_id, m.user_email, m.role = str(uuid4()), str(uuid4()), "new@example.com", "member"
    m.joined_at, m.invited_by, m.is_active, m.grant_source = datetime.now(timezone.utc), "admin@example.com", True, None
    return m


def _service(role, **calls):
    service = AsyncMock(spec=TeamManagementService)
    service.get_user_role_in_team = AsyncMock(return_value=role)
    for name, value in calls.items():
        setattr(service, name, AsyncMock(return_value=value))
    return service


def _admin(is_admin):
    perm = AsyncMock()
    perm.check_platform_admin_permission = AsyncMock(return_value=is_admin)
    return patch("mcpgateway.routers.teams.PermissionService", return_value=perm)


@pytest.mark.asyncio
async def test_admin_outside_the_team_lists_its_members(db, user, member):
    from mcpgateway.routers.teams import list_team_members

    who = MagicMock(spec=EmailUser)
    who.email, who.full_name = member.user_email, "New"
    with patch("mcpgateway.routers.teams.TeamManagementService", return_value=_service(None, get_team_members=[(who, member)])), _admin(True):
        result = await list_team_members(team_id="t1", cursor=None, limit=None, include_pagination=False, current_user=user, db=db)
    assert [m.user_email for m in result] == ["new@example.com"]


@pytest.mark.asyncio
async def test_admin_outside_the_team_adds_changes_and_removes_members(db, user, member):
    from mcpgateway.routers.teams import add_team_member, remove_team_member, update_team_member

    service = _service(None, add_member_to_team=member, update_member_role=True, get_member=member, remove_member_from_team=True)
    with patch("mcpgateway.routers.teams.TeamManagementService", return_value=service), _admin(True):
        added = await add_team_member("t1", TeamMemberAddRequest(email="new@example.com", role="member"), current_user=user, db=db)
        await update_team_member("t1", "new@example.com", TeamMemberUpdateRequest(role="member"), current_user=user, db=db)
        removed = await remove_team_member("t1", "new@example.com", current_user=user, db=db)
    assert added.user_email == "new@example.com" and removed.success
    service.add_member_to_team.assert_awaited_once_with("t1", "new@example.com", "member", invited_by="admin@example.com")
    service.remove_member_from_team.assert_awaited_once_with("t1", "new@example.com")


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [None, "member"])
async def test_non_admin_non_owner_is_still_refused(db, user, role):
    from mcpgateway.routers.teams import add_team_member, list_team_members, remove_team_member

    with patch("mcpgateway.routers.teams.TeamManagementService", return_value=_service(role)), _admin(False):
        if role is None:
            with pytest.raises(HTTPException) as listed:
                await list_team_members(team_id="t1", cursor=None, limit=None, include_pagination=False, current_user=user, db=db)
            assert listed.value.status_code == status.HTTP_403_FORBIDDEN
        for call in (add_team_member("t1", TeamMemberAddRequest(email="x@example.com", role="member"), current_user=user, db=db),
                     remove_team_member("t1", "x@example.com", current_user=user, db=db)):
            with pytest.raises(HTTPException) as refused:
                await call
            assert refused.value.status_code == status.HTTP_403_FORBIDDEN
