# -*- coding: utf-8 -*-
"""A tool whose own name already starts with its gateway's slug isn't prefixed again (TOOL_NAME_SKIP_REPEATED_PREFIX)."""

# Standard
from unittest.mock import MagicMock

# Third-Party
import pytest
from sqlalchemy import create_engine, literal, select

# First-Party
from mcpgateway import db
from mcpgateway.config import settings


def _named(original, gateway="Slack", custom=None):
    tool = db.Tool(original_name=original, gateway_id="gw-1", custom_name=custom)
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = (gateway,)
    db.set_custom_name_and_slug(None, connection, tool)
    return tool.name


@pytest.fixture
def skip_on(monkeypatch):
    monkeypatch.setattr(settings, "tool_name_skip_repeated_prefix", True)
    monkeypatch.setattr(settings, "gateway_tool_name_separator", "-")


def test_off_by_default_names_stay_as_today(monkeypatch):
    monkeypatch.setattr(settings, "tool_name_skip_repeated_prefix", False)
    assert _named("slack_search_public") == "slack-slack-search-public"


def test_a_name_starting_with_the_gateway_slug_is_not_prefixed_again(skip_on):
    assert _named("slack_search_public") == "slack-search-public"
    assert _named("Slack Search Public") == "slack-search-public", "normalised the same way as the gateway slug"


def test_other_names_keep_the_prefix(skip_on):
    assert _named("search_public") == "slack-search-public"
    assert _named("slacker_tool") == "slack-slacker-tool", "only a whole-word prefix counts"
    assert _named("slack") == "slack-slack", "a name that is only the slug keeps the prefix"


def test_custom_names_still_work(skip_on):
    assert _named("slack_search_public", custom="search public") == "slack-search-public"
    assert _named("slack_search_public", custom="find messages") == "slack-find-messages"


@pytest.mark.parametrize(("slug", "expected"), [("slack-search-public", "slack-search-public"), ("search", "slack-search"), ("slack", "slack-slack")])
def test_a_gateway_rename_follows_the_same_rule(skip_on, slug, expected):
    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        assert connection.execute(select(db._joined_tool_name_sql("slack", "-", literal(slug)))).scalar_one() == expected
