# -*- coding: utf-8 -*-
"""An authorization_code gateway reloads its tools with every person's sign-in, and keeps them when the
gateway itself (no person's token) gets an empty answer."""

# Standard
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party
import pytest

# First-Party
from mcpgateway.routers.oauth_router import _load_tools_on_sign_in
from mcpgateway.services.gateway_service import GatewayCatalogSyncResult, GatewayService


def _gateway(tools, grant_type="authorization_code"):
    return SimpleNamespace(id="gw-1", tools=list(tools), resources=[], prompts=[], oauth_config={"grant_type": grant_type})


def _empty_answer():
    return GatewayCatalogSyncResult(new_tool_names=[], new_resource_uris=[], new_prompt_names=[], tools_to_add=[], resources_to_add=[], prompts_to_add=[])


@pytest.mark.asyncio
async def test_a_sign_in_loads_the_tools_with_that_persons_token():
    fetch = AsyncMock(return_value={"tools": [object()] * 18})
    with patch("mcpgateway.services.gateway_service.GatewayService.fetch_tools_after_oauth", fetch):
        await _load_tools_on_sign_in(MagicMock(), _gateway([]), "member@acme.example", "team-acme")
    fetch.assert_awaited_once()
    assert fetch.await_args.args[1:] == ("gw-1", "member@acme.example")
    assert fetch.await_args.kwargs == {"teams": ["team-acme"]}


@pytest.mark.asyncio
async def test_later_sign_ins_reload_a_list_that_already_has_tools():
    fetch = AsyncMock(return_value={"tools": []})
    with patch("mcpgateway.services.gateway_service.GatewayService.fetch_tools_after_oauth", fetch):
        await _load_tools_on_sign_in(MagicMock(), _gateway([SimpleNamespace(original_name="search")]), "b@acme.example", None)
    fetch.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_failed_load_never_fails_the_sign_in():
    with patch("mcpgateway.services.gateway_service.GatewayService.fetch_tools_after_oauth", AsyncMock(side_effect=RuntimeError("upstream down"))):
        await _load_tools_on_sign_in(MagicMock(), _gateway([]), "member@acme.example", None)


def test_an_empty_answer_without_a_persons_token_keeps_the_tools():
    tools = [SimpleNamespace(id=f"t{i}", original_name=f"tool_{i}", created_via="oauth") for i in range(3)]
    gateway, db = _gateway(tools), MagicMock()
    result = GatewayService()._reconcile_gateway_catalog(db, gateway=gateway, catalog_sync=_empty_answer(), log_context="gateway update")
    assert result.tools_removed == 0 and len(gateway.tools) == 3
    db.execute.assert_not_called()


def test_other_gateways_still_drop_tools_the_server_no_longer_has():
    tools = [SimpleNamespace(id="t1", original_name="gone", created_via="update")]
    gateway, db = _gateway(tools, grant_type="client_credentials"), MagicMock()
    result = GatewayService()._reconcile_gateway_catalog(db, gateway=gateway, catalog_sync=_empty_answer(), log_context="gateway update")
    assert result.tools_removed == 1 and db.execute.called
