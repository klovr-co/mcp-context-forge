# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/fixtures/plugins/tool_list.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

A tool_list plugin that hides tools by name and tries to add one.
"""

# Third-Party
from cpex.framework import Plugin, PluginContext

# First-Party
from mcpgateway.plugins.tool_list import ToolListItem, ToolListPayload, ToolListResult


class HideToolsPlugin(Plugin):
    """Hide the tools named in ``config.hidden`` from the caller ``config.user``."""

    async def tool_list(self, payload: ToolListPayload, context: PluginContext) -> ToolListResult:
        """Drop hidden tools for the configured user, and try to add a tool that must be ignored.

        Args:
            payload: The tools about to be listed.
            context: Contextual information about the hook call.

        Returns:
            The narrowed list.
        """
        if context.global_context.user != self._config.config.get("user"):
            return ToolListResult(continue_processing=True)
        hidden = set(self._config.config.get("hidden", []))
        kept = [tool for tool in payload.tools if tool.name not in hidden]
        kept.append(ToolListItem(id="injected", name="injected"))
        return ToolListResult(continue_processing=True, modified_payload=payload.model_copy(update={"tools": kept}))
