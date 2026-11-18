# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/plugins/tool_list.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

The ``tool_list`` plugin hook.

Plugins registered on ``tool_list`` see the tools a caller is about to receive
from ``tools/list`` and can drop some of them, for example to hide tools a
policy engine would refuse at call time.  A plugin can only narrow the list:
tools it adds or renames are ignored.  Hiding a tool does not block calls to
it; pair the plugin with a ``tool_pre_invoke`` check for that.

Examples:
    >>> from mcpgateway.plugins.tool_list import TOOL_LIST, ToolListItem, ToolListPayload
    >>> TOOL_LIST
    'tool_list'
    >>> payload = ToolListPayload(server_id="srv1", tools=[ToolListItem(id="t1", name="search")])
    >>> [tool.name for tool in payload.tools]
    ['search']
"""

# Standard
from collections.abc import Sequence
import logging
from typing import Any, Optional, TypeVar
import uuid

# Third-Party
from cpex.framework import GlobalContext, PluginPayload, PluginResult
from cpex.framework.hooks.registry import get_hook_registry
from pydantic import BaseModel

# First-Party
from mcpgateway.config import settings
from mcpgateway.plugins import DEFAULT_SERVER_ID, get_plugin_manager
from mcpgateway.utils.correlation_id import get_correlation_id
from mcpgateway.utils.gateway_arguments import listed_gateway_arguments

logger = logging.getLogger(__name__)

TOOL_LIST = "tool_list"

T = TypeVar("T")


class ToolListItem(BaseModel):
    """One tool in a ``tools/list`` result, as seen by a ``tool_list`` plugin.

    Attributes:
        id: Tool id.
        name: Gateway-scoped tool name, as listed to the client.
        original_name: Name of the tool on its upstream server.
        gateway_id: Upstream gateway id.
        team_id: Owning team id.
        gateway_arguments: Set by a plugin to replace the gateway arguments listed for this
            tool and caller, as {name: JSON schema}; ``{}`` lists none. None keeps the defaults.
        required_gateway_arguments: Gateway arguments to list as required for this tool.
    """

    id: str
    name: str
    original_name: Optional[str] = None
    gateway_id: Optional[str] = None
    team_id: Optional[str] = None
    gateway_arguments: Optional[dict[str, dict[str, Any]]] = None
    required_gateway_arguments: list[str] = []


class ToolListPayload(PluginPayload):
    """Payload for the ``tool_list`` hook.

    Attributes:
        server_id: Virtual server being listed, or None for the gateway-wide list.
        tools: Tools the caller is allowed to see before plugins run.
    """

    server_id: Optional[str] = None
    tools: list[ToolListItem]


ToolListResult = PluginResult[ToolListPayload]


def _register_tool_list_hook() -> None:
    """Register the hook's payload and result types in the global registry."""
    registry = get_hook_registry()
    if not registry.is_registered(TOOL_LIST):
        registry.register_hook(TOOL_LIST, ToolListPayload, ToolListResult)


_register_tool_list_hook()


def _as_item(tool: object) -> ToolListItem:
    """Describe a database row or ``ToolRead`` for plugins.

    Args:
        tool: Object with ``id`` and ``name`` attributes.

    Returns:
        The plugin-facing description of the tool.
    """
    return ToolListItem(
        id=str(getattr(tool, "id")),
        name=getattr(tool, "name"),
        original_name=getattr(tool, "original_name", None),
        gateway_id=getattr(tool, "gateway_id", None),
        team_id=getattr(tool, "team_id", None),
    )


async def filter_listed_tools(tools: Sequence[T], *, server_id: Optional[str], user_email: Optional[str]) -> list[T]:
    """Run ``tool_list`` plugins and keep only the tools they returned.

    Order is preserved.  With no plugin on the hook, or a plugin that returns
    no modified payload, every tool is kept.  Violations and plugin errors
    propagate according to the plugin's mode, so a failing enforcing plugin
    fails the listing instead of exposing every tool.

    Args:
        tools: Tools already filtered by visibility, as ORM rows or ``ToolRead``.
        server_id: Virtual server being listed, or None.
        user_email: Caller's email, if known.

    Returns:
        The tools the plugins kept.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import patch
        >>> async def no_manager(server_id):
        ...     return None
        >>> with patch("mcpgateway.plugins.tool_list.get_plugin_manager", no_manager):
        ...     asyncio.run(filter_listed_tools(["a"], server_id=None, user_email=None))
        ['a']
    """
    listed_gateway_arguments(None)
    if not tools:
        return list(tools)
    plugin_manager = await get_plugin_manager(server_id or DEFAULT_SERVER_ID)
    if not plugin_manager or not plugin_manager.has_hooks_for(TOOL_LIST):
        return list(tools)

    global_context = GlobalContext(request_id=get_correlation_id() or uuid.uuid4().hex, user=user_email, server_id=server_id)
    payload = ToolListPayload(server_id=server_id, tools=[_as_item(tool) for tool in tools])
    result, _ = await plugin_manager.invoke_hook(TOOL_LIST, payload=payload, global_context=global_context, violations_as_exceptions=True)
    if result.modified_payload is None:
        return list(tools)

    kept = {item.id for item in result.modified_payload.tools}
    listed_gateway_arguments(
        {
            item.id: (item.gateway_arguments if item.gateway_arguments is not None else settings.tool_gateway_arguments, item.required_gateway_arguments)
            for item in result.modified_payload.tools
            if item.gateway_arguments is not None or item.required_gateway_arguments
        }
    )
    filtered = [tool for tool in tools if str(getattr(tool, "id")) in kept]
    if len(filtered) != len(tools):
        logger.debug("tool_list plugins hid %d of %d tools for %s", len(tools) - len(filtered), len(tools), user_email)
    return filtered
