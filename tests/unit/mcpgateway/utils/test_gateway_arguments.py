# -*- coding: utf-8 -*-
"""Gateway arguments: listed on every tool, skipped by the input check, removed before the upstream call."""

# Third-Party
import pytest

# First-Party
from mcpgateway.config import settings
from mcpgateway.services.tool_service import _validate_tool_input_arguments
from mcpgateway.transports.streamablehttp_transport import _to_mcp_tool
from mcpgateway.utils.gateway_arguments import with_gateway_arguments, without_gateway_arguments

ACCOUNT = {"account": {"type": "string", "description": "Which account to use"}}
STRICT = {"type": "object", "additionalProperties": False, "properties": {"query": {"type": "string"}}, "required": ["query"]}


@pytest.fixture
def account_argument(monkeypatch):
    monkeypatch.setattr(settings, "tool_gateway_arguments", ACCOUNT)


class _Tool:
    name = "gmail-search"
    title = None
    description = "Search mail"
    input_schema = STRICT
    output_schema = None
    annotations = None
    extension_metadata = None


def test_listed_tool_offers_the_gateway_argument(account_argument):
    listed = _to_mcp_tool(_Tool()).input_schema
    assert listed["properties"]["account"] == ACCOUNT["account"]
    assert listed["properties"]["query"] == {"type": "string"}
    assert listed["additionalProperties"] is False
    assert "account" not in STRICT["properties"], "the stored schema is not changed"


def test_strict_schema_accepts_the_gateway_argument(account_argument):
    assert _validate_tool_input_arguments({"query": "invoice", "account": "company account"}, STRICT) is None


def test_strict_schema_still_refuses_other_extra_fields(account_argument):
    assert "unexpected" in _validate_tool_input_arguments({"query": "invoice", "folder": "x"}, STRICT)


def test_gateway_argument_never_reaches_the_upstream(account_argument):
    assert without_gateway_arguments({"query": "invoice", "account": "company account"}, STRICT) == {"query": "invoice"}


def test_a_tool_that_declares_the_same_name_keeps_its_own(account_argument):
    own = {"type": "object", "properties": {"account": {"type": "integer"}}}
    assert with_gateway_arguments(own)["properties"]["account"] == {"type": "integer"}
    assert without_gateway_arguments({"account": 7}, own) == {"account": 7}


def test_nothing_changes_without_the_setting(monkeypatch):
    monkeypatch.setattr(settings, "tool_gateway_arguments", {})
    assert with_gateway_arguments(STRICT) is STRICT
    assert "unexpected" in _validate_tool_input_arguments({"query": "invoice", "account": "x"}, STRICT)


@pytest.mark.asyncio
async def test_a_tool_list_plugin_sets_each_callers_accounts(account_argument, monkeypatch):
    # Third-Party
    from unittest.mock import AsyncMock, MagicMock

    # First-Party
    from mcpgateway.plugins import tool_list
    from mcpgateway.plugins.tool_list import filter_listed_tools, ToolListResult

    accounts = {"account": {"type": "string", "enum": ["Team A", "Team B"], "description": "Which Slack to use: Team A, Team B. Ask the person if it isn't clear."}}
    slack, gmail, fal = (_Tool(), _Tool(), _Tool())
    slack.id, gmail.id, fal.id = "slack", "gmail", "fal"

    async def plugin(_hook, payload, **_kwargs):
        items = []
        for item in payload.tools:
            if item.id == "slack":
                item = item.model_copy(update={"gateway_arguments": accounts, "required_gateway_arguments": ["account"]})
            elif item.id == "gmail":
                item = item.model_copy(update={"gateway_arguments": {}})
            items.append(item)
        return ToolListResult(modified_payload=payload.model_copy(update={"tools": items})), None

    manager = MagicMock()
    manager.has_hooks_for.return_value = True
    manager.invoke_hook = AsyncMock(side_effect=plugin)
    monkeypatch.setattr(tool_list, "get_plugin_manager", AsyncMock(return_value=manager))

    await filter_listed_tools([slack, gmail, fal], server_id="bundle", user_email="person@example.com")
    slack_schema, gmail_schema, fal_schema = (_to_mcp_tool(tool).input_schema for tool in (slack, gmail, fal))

    assert slack_schema["properties"]["account"] == accounts["account"]
    assert slack_schema["required"] == ["query", "account"]
    assert "account" not in gmail_schema["properties"], "one account: the field is left out"
    assert fal_schema["properties"]["account"] == ACCOUNT["account"], "a tool the plugin left alone keeps the default"
    assert STRICT["required"] == ["query"], "the stored schema is not changed"

    await filter_listed_tools([], server_id="bundle", user_email="other@example.com")
    assert _to_mcp_tool(slack).input_schema["properties"]["account"] == ACCOUNT["account"], "a new listing starts from the defaults"
