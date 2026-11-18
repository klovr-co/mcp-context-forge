# -*- coding: utf-8 -*-
"""Same-name tools in two teams that call the same upstream: one is picked when the setting is on."""

# Standard
from types import SimpleNamespace
from unittest.mock import MagicMock

# Third-Party
import pytest

# First-Party
from mcpgateway.config import settings
from mcpgateway.services import tool_service as module
from mcpgateway.services.tool_service import ToolInvocationError, ToolService


def _tool(tool_id, gateway_id, url="https://mcp.example.com/mcp", original="search"):
    gateway = SimpleNamespace(url=url)
    return SimpleNamespace(id=tool_id, gateway_id=gateway_id, gateway=gateway, original_name=original, visibility="team", team_id=f"team-{gateway_id}", owner_email="x@example.com")


async def _select(service, tools):
    service._load_invocable_tools = MagicMock(return_value=tools)

    async def allowed(*_args, **_kwargs):
        return True

    service._check_tool_access = allowed
    return await service._select_invocable_tool(MagicMock(), "slack-search", user_email="person@example.com", token_teams=None, server_id="bundle")


@pytest.mark.asyncio
async def test_off_by_default_two_teams_stay_ambiguous(monkeypatch):
    monkeypatch.setattr(settings, "tool_same_name_across_teams", False)
    with pytest.raises(ToolInvocationError, match="ambiguous"):
        await _select(ToolService(), [_tool("b", "g2"), _tool("a", "g1")])


@pytest.mark.asyncio
async def test_on_picks_one_and_names_every_candidate(monkeypatch):
    monkeypatch.setattr(settings, "tool_same_name_across_teams", True)
    module._same_name_gateway_ids.set(())
    tool, caller_dependent = await _select(ToolService(), [_tool("b", "g2"), _tool("a", "g1", url="https://mcp.example.com/mcp/")])
    assert tool.id == "a", "a stable pick"
    assert caller_dependent, "never cached for other callers"
    assert module._same_name_gateway_ids.get() == ("g1", "g2")


@pytest.mark.asyncio
@pytest.mark.parametrize("other", [_tool("b", "g2", url="https://other.example.com/mcp"), _tool("b", "g2", original="send")])
async def test_on_still_refuses_different_upstreams(monkeypatch, other):
    monkeypatch.setattr(settings, "tool_same_name_across_teams", True)
    with pytest.raises(ToolInvocationError, match="ambiguous"):
        await _select(ToolService(), [_tool("a", "g1"), other])

