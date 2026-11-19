# -*- coding: utf-8 -*-
"""A tool's own failure on /rpc (for example, not signed in to its gateway) reaches the caller as a readable
tool error, as on the streamable HTTP transport, not as -32603 "Internal error"."""

# Standard
from unittest.mock import AsyncMock, patch

# Third-Party
import pytest

# First-Party
from mcpgateway.services.tool_service import ToolInvocationError, _signed_out_message
from tests.helpers.auth import make_auth_headers
from tests.unit.mcpgateway.test_rpc_scoped_authorization import SERVER_A_ID, _rpc_body, _token, scoped_rpc_client  # noqa: F401  (fixture)


def test_rpc_tool_failure_is_a_readable_tool_error(scoped_rpc_client):  # noqa: F811
    message = "You're not signed in to slack. Sign in at https://app.example.org/connectors, then try again."
    with (
        patch("mcpgateway.main._maybe_forward_affinitized_rpc_request", new_callable=AsyncMock, return_value=None),
        patch("mcpgateway.main._execute_rpc_tools_call", new_callable=AsyncMock, side_effect=ToolInvocationError(message)),
    ):
        response = scoped_rpc_client.post("/rpc", headers=make_auth_headers(_token(permissions=["tools.execute"])), json=_rpc_body(SERVER_A_ID))
    assert response.status_code == 200
    body = response.json()
    assert "error" not in body
    assert body["result"] == {"content": [{"type": "text", "text": message}], "isError": True}


def test_rpc_unexpected_failure_is_still_internal_error(scoped_rpc_client):  # noqa: F811
    with (
        patch("mcpgateway.main._maybe_forward_affinitized_rpc_request", new_callable=AsyncMock, return_value=None),
        patch("mcpgateway.main._execute_rpc_tools_call", new_callable=AsyncMock, side_effect=RuntimeError("boom")),
    ):
        response = scoped_rpc_client.post("/rpc", headers=make_auth_headers(_token(permissions=["tools.execute"])), json=_rpc_body(SERVER_A_ID))
    assert response.json()["error"]["code"] == -32603
    assert "boom" not in response.text


def test_message_points_to_the_sign_in_page_when_set(monkeypatch):
    monkeypatch.setenv("OAUTH_SIGNIN_PAGE_URL", "https://app.example.org/connectors")
    assert _signed_out_message("slack", "g1") == "You're not signed in to slack. Sign in at https://app.example.org/connectors, then try again."


@pytest.mark.parametrize("value", ["", "app.example.org/connectors", "javascript:alert(1)"])
def test_message_keeps_the_gateways_own_address_otherwise(monkeypatch, value):
    monkeypatch.setenv("OAUTH_SIGNIN_PAGE_URL", value)
    assert _signed_out_message("slack", "g1") == "Please authorize slack first. Visit /oauth/authorize/g1 to complete OAuth flow."
