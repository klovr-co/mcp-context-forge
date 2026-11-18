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


@pytest.mark.parametrize(
    ("gateway_slug", "slug", "expected"),
    [("slack", "slack-search-public", "slack-search-public"), ("slack", "search", "slack-search"), ("slack", "slack", "slack-slack"), ("", "search", "search")],
)
def test_a_gateway_rename_follows_the_same_rule(skip_on, gateway_slug, slug, expected):
    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        assert connection.execute(select(db._joined_tool_name_sql(gateway_slug, "-", literal(slug)))).scalar_one() == expected


def test_the_startup_refresh_keeps_a_name_another_tool_already_has(skip_on, monkeypatch):
    """slack_search (stored doubled) and a custom-named search would both become slack-search; the second keeps its name."""
    # Standard
    from types import SimpleNamespace

    gateway = SimpleNamespace(name="slack")
    first = SimpleNamespace(id="1", name="slack-slack-search", custom_name_slug="slack-search", original_name="slack_search", gateway=gateway, team_id="t", owner_email="o")
    second = SimpleNamespace(id="2", name="slack-something", custom_name_slug="search", original_name="something", gateway=gateway, team_id="t", owner_email="o")
    taken = {"slack-search": "2"}

    def name_taken(_session, tool, name):
        return taken.get(name) not in (None, tool.id)

    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.side_effect = [[first, second], []]
    monkeypatch.setattr(db, "_tool_name_taken", name_taken)
    db._refresh_tool_names_batched(session, 10)
    assert first.name == "slack-slack-search", "kept: slack-search belongs to the other tool"
    assert second.name == "slack-search"
