# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/utils/gateway_arguments.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Gateway arguments: tool arguments that belong to the gateway, not the upstream server.

``settings.tool_gateway_arguments`` names them, for example
``{"account": {"type": "string", "description": "Which account to use"}}``.
The gateway adds them to every tool it lists, leaves them out of the tool's
input check, hands them to ``tool_pre_invoke`` plugins with the other
arguments, and removes them before the call reaches the upstream server.
A tool whose own schema already has an argument of that name keeps its own,
untouched. With the setting empty, nothing changes.

A ``tool_list`` plugin may replace them per tool for one listing, for example
to list the caller's own accounts in the ``account`` description, or to hide
the argument for a caller with one account. See ``listed_gateway_arguments``.

"""

# Standard
from contextvars import ContextVar
from typing import Any, Dict, List, Optional, Tuple

# First-Party
from mcpgateway.config import settings


ListedArguments = Tuple[Dict[str, Dict[str, Any]], List[str]]
"""Per-tool gateway arguments for one listing: ({name: JSON schema}, names to mark required)."""

_listed: ContextVar[Optional[Dict[str, ListedArguments]]] = ContextVar("listed_gateway_arguments", default=None)


def listed_gateway_arguments(per_tool: Optional[Dict[str, ListedArguments]]) -> None:
    """Set the per-tool gateway arguments for the listing being built in this context.

    ``tool_list`` plugins decide them; the listing's serializer reads them through
    ``with_gateway_arguments(schema, tool_id)``. Tools not named keep the defaults.

    Args:
        per_tool: {tool id: (arguments, required names)}, or None for defaults everywhere.

    Examples:
        >>> listed_gateway_arguments({"t1": ({}, [])})
        >>> with_gateway_arguments({"type": "object", "properties": {"q": {}}}, "t1")
        {'type': 'object', 'properties': {'q': {}}}
        >>> listed_gateway_arguments(None)
    """
    _listed.set(per_tool)


def with_gateway_arguments(input_schema: Optional[Dict[str, Any]], tool_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return the schema a client sees: the tool's own schema plus the gateway arguments.

    Args:
        input_schema: The tool's stored input schema.
        tool_id: The tool's id, to use arguments a ``tool_list`` plugin set for it.

    Returns:
        A new schema with the gateway arguments added, or the original when none apply
        or the schema isn't an object schema.

    Examples:
        >>> with_gateway_arguments(None) is None
        True
    """
    override = (_listed.get() or {}).get(str(tool_id)) if tool_id is not None else None
    extra, required = override if override is not None else (settings.tool_gateway_arguments, [])
    if not extra or not isinstance(input_schema, dict) or input_schema.get("type", "object") != "object":
        return input_schema
    own = input_schema.get("properties") or {}
    properties = dict(own)
    for name, schema in extra.items():
        properties.setdefault(name, schema)
    schema = {**input_schema, "properties": properties}
    added_required = [name for name in required if name in extra and name not in own]
    if added_required:
        schema["required"] = list(input_schema.get("required") or []) + [name for name in added_required if name not in (input_schema.get("required") or [])]
    return schema


def without_gateway_arguments(arguments: Optional[Dict[str, Any]], input_schema: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return the arguments with the gateway arguments removed, keeping any the tool declares itself.

    Args:
        arguments: Arguments as the client or a plugin left them.
        input_schema: The tool's stored input schema.

    Returns:
        The same dict when there is nothing to remove, otherwise a copy without them.

    Examples:
        >>> without_gateway_arguments(None, None) is None
        True
        >>> from unittest.mock import patch
        >>> with patch("mcpgateway.utils.gateway_arguments.settings") as s:
        ...     s.tool_gateway_arguments = {"account": {"type": "string"}}
        ...     without_gateway_arguments({"account": "own"}, {"properties": {"account": {}}})
        {'account': 'own'}
    """
    extra = settings.tool_gateway_arguments
    if not extra or not isinstance(arguments, dict):
        return arguments
    own = (input_schema.get("properties") or {}) if isinstance(input_schema, dict) else {}
    remove = {name for name in extra if name in arguments and name not in own}
    if not remove:
        return arguments
    return {key: value for key, value in arguments.items() if key not in remove}
