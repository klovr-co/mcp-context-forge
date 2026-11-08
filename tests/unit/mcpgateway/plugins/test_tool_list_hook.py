# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/test_tool_list_hook.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the tool_list plugin hook.
"""

# Standard
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

# Third-Party
from cpex.framework import PluginManager, PluginViolation, PluginViolationError
import pytest

# First-Party
from mcpgateway.plugins import tool_list
from mcpgateway.plugins.policy import HOOK_PAYLOAD_POLICIES
from mcpgateway.plugins.tool_list import filter_listed_tools, TOOL_LIST, ToolListItem, ToolListPayload, ToolListResult

TOOLS = [SimpleNamespace(id=f"t{i}", name=name, original_name=name, gateway_id="g1", team_id="team1") for i, name in enumerate(["search", "create_order", "refund_order"])]


def _manager(result=None, has_hooks=True, side_effect=None):
    """Build a fake plugin manager returning ``result`` from the tool_list hook."""
    manager = MagicMock()
    manager.has_hooks_for.return_value = has_hooks
    manager.invoke_hook = AsyncMock(return_value=(result, None), side_effect=side_effect)
    return manager


def _use(monkeypatch, manager):
    """Make ``get_plugin_manager`` return ``manager``."""
    monkeypatch.setattr(tool_list, "get_plugin_manager", AsyncMock(return_value=manager))


@pytest.mark.asyncio
async def test_no_plugin_manager_keeps_everything(monkeypatch):
    _use(monkeypatch, None)
    assert await filter_listed_tools(TOOLS, server_id="s1", user_email="a@example.com") == TOOLS


@pytest.mark.asyncio
async def test_no_tool_list_plugin_keeps_everything(monkeypatch):
    manager = _manager(has_hooks=False)
    _use(monkeypatch, manager)
    assert await filter_listed_tools(TOOLS, server_id="s1", user_email="a@example.com") == TOOLS
    manager.has_hooks_for.assert_called_once_with(TOOL_LIST)
    manager.invoke_hook.assert_not_called()


@pytest.mark.asyncio
async def test_empty_list_skips_plugins(monkeypatch):
    manager = _manager()
    _use(monkeypatch, manager)
    assert await filter_listed_tools([], server_id="s1", user_email="a@example.com") == []
    manager.invoke_hook.assert_not_called()


@pytest.mark.asyncio
async def test_unmodified_payload_keeps_everything(monkeypatch):
    _use(monkeypatch, _manager(ToolListResult(continue_processing=True)))
    assert await filter_listed_tools(TOOLS, server_id="s1", user_email="a@example.com") == TOOLS


@pytest.mark.asyncio
async def test_plugin_narrows_and_cannot_add(monkeypatch):
    kept = [ToolListItem(id="t2", name="refund_order"), ToolListItem(id="t0", name="search"), ToolListItem(id="new", name="new")]
    manager = _manager(ToolListResult(modified_payload=ToolListPayload(server_id="s1", tools=kept)))
    _use(monkeypatch, manager)

    result = await filter_listed_tools(TOOLS, server_id="s1", user_email="a@example.com")

    assert [tool.name for tool in result] == ["search", "refund_order"]  # original order, nothing added
    kwargs = manager.invoke_hook.call_args.kwargs
    assert kwargs["global_context"].user == "a@example.com"
    assert kwargs["global_context"].server_id == "s1"
    assert [item.model_dump() for item in kwargs["payload"].tools][0] == {"id": "t0", "name": "search", "original_name": "search", "gateway_id": "g1", "team_id": "team1"}


@pytest.mark.asyncio
async def test_violation_fails_the_listing(monkeypatch):
    violation = PluginViolation(reason="denied", description="denied", code="DENIED", details={})
    _use(monkeypatch, _manager(side_effect=PluginViolationError("denied", violation=violation)))
    with pytest.raises(PluginViolationError):
        await filter_listed_tools(TOOLS, server_id="s1", user_email="a@example.com")


def test_payload_policy_allows_only_tools():
    assert HOOK_PAYLOAD_POLICIES[TOOL_LIST].writable_fields == frozenset({"tools"})


@pytest.mark.asyncio
async def test_real_plugin_manager_hides_tools(monkeypatch):
    PluginManager.reset()
    manager = PluginManager("./tests/unit/mcpgateway/plugins/fixtures/configs/tool_list_hide.yaml", hook_policies=HOOK_PAYLOAD_POLICIES)
    await manager.initialize()
    try:
        _use(monkeypatch, manager)
        blocked = await filter_listed_tools(TOOLS, server_id="s1", user_email="blocked@example.com")
        other = await filter_listed_tools(TOOLS, server_id="s1", user_email="other@example.com")
    finally:
        await manager.shutdown()
        PluginManager.reset()

    assert [tool.name for tool in blocked] == ["search", "create_order"]
    assert other == TOOLS
