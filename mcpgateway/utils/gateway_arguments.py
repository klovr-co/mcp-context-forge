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

"""

# Standard
from typing import Any, Dict, Optional

# First-Party
from mcpgateway.config import settings


def with_gateway_arguments(input_schema: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return the schema a client sees: the tool's own schema plus the gateway arguments.

    Args:
        input_schema: The tool's stored input schema.

    Returns:
        A new schema with the gateway arguments added, or the original when none are set
        or the schema isn't an object schema.

    Examples:
        >>> with_gateway_arguments(None) is None
        True
    """
    extra = settings.tool_gateway_arguments
    if not extra or not isinstance(input_schema, dict) or input_schema.get("type", "object") != "object":
        return input_schema
    properties = dict(input_schema.get("properties") or {})
    for name, schema in extra.items():
        properties.setdefault(name, schema)
    return {**input_schema, "properties": properties}


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
