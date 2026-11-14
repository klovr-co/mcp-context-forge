# -*- coding: utf-8 -*-
"""The downstream client's protocol envelope in ``_meta`` is never forwarded upstream.

A 2026-07-28 client stamps its protocol version, client info and capabilities into
every request's ``_meta``. Forwarding them breaks handshake-era upstreams: one
rejects any body-borne version (-32022), another rejects a body version that
disagrees with the negotiated ``MCP-Protocol-Version`` header.
"""

# Standard
from unittest.mock import AsyncMock, MagicMock

# Third-Party
from mcp_types import CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, PROTOCOL_VERSION_META_KEY
import pytest

# First-Party
from mcpgateway.common.validators import without_client_envelope
from mcpgateway.services.prompt_service import _get_prompt_with_meta
from mcpgateway.services.resource_service import _read_resource_with_meta
from mcpgateway.services.tool_service import _call_upstream_tool

ENVELOPE = {
    PROTOCOL_VERSION_META_KEY: "2026-07-28",
    CLIENT_INFO_META_KEY: {"name": "claude-ai", "version": "1"},
    CLIENT_CAPABILITIES_META_KEY: {},
}


def test_strips_only_the_envelope():
    assert without_client_envelope({**ENVELOPE, "traceparent": "t", "user": {"id": "a"}}) == {"traceparent": "t", "user": {"id": "a"}}


def test_envelope_only_becomes_none():
    assert without_client_envelope(dict(ENVELOPE)) is None
    assert without_client_envelope({}) is None
    assert without_client_envelope(None) is None


def test_input_is_not_mutated():
    meta = {**ENVELOPE, "traceparent": "t"}
    without_client_envelope(meta)
    assert PROTOCOL_VERSION_META_KEY in meta


@pytest.mark.asyncio
async def test_tool_call_drops_envelope():
    session = MagicMock()
    session._x_mcp_header_maps = {}
    session.call_tool = AsyncMock(return_value="ok")
    await _call_upstream_tool(
        session,
        "search",
        {"q": "x"},
        input_schema={},
        meta={**ENVELOPE, "traceparent": "t"},
        progress_callback=None,
        input_responses=None,
        request_state=None,
    )
    assert session.call_tool.await_args.kwargs["meta"] == {"traceparent": "t"}


@pytest.mark.asyncio
async def test_tool_call_with_envelope_only_sends_no_meta():
    session = MagicMock()
    session._x_mcp_header_maps = {}
    session.call_tool = AsyncMock(return_value="ok")
    await _call_upstream_tool(session, "search", {}, input_schema={}, meta=dict(ENVELOPE), progress_callback=None, input_responses=None, request_state=None)
    assert session.call_tool.await_args.kwargs["meta"] is None


@pytest.mark.asyncio
async def test_prompt_with_envelope_only_uses_plain_get_prompt():
    session = MagicMock()
    session.get_prompt = AsyncMock(return_value="ok")
    session.send_request = AsyncMock()
    await _get_prompt_with_meta(session, "p", None, dict(ENVELOPE))
    session.get_prompt.assert_awaited_once()
    session.send_request.assert_not_awaited()


@pytest.mark.asyncio
async def test_resource_with_envelope_only_uses_plain_read():
    session = MagicMock()
    session.read_resource = AsyncMock(return_value="ok")
    session.send_request = AsyncMock()
    await _read_resource_with_meta(session, "file:///x", dict(ENVELOPE))
    session.read_resource.assert_awaited_once()
    session.send_request.assert_not_awaited()
