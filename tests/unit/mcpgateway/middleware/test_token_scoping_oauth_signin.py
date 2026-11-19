# -*- coding: utf-8 -*-
"""A token with a permission list may start and end a person's own sign-in to a gateway with gateways.read."""

# Third-Party
import pytest

# First-Party
from mcpgateway.db import Permissions
from mcpgateway.middleware.token_scoping import TokenScopingMiddleware


@pytest.fixture
def middleware():
    return TokenScopingMiddleware()


@pytest.mark.parametrize("method,path", [("GET", "/oauth/authorize/gw1"), ("DELETE", "/oauth/tokens/gw1")])
def test_gateways_read_is_enough(middleware, method, path):
    assert middleware._check_permission_restrictions(path, method, [Permissions.GATEWAYS_READ]) is True
    assert middleware._check_permission_restrictions(path, method, ["*"]) is True


@pytest.mark.parametrize("method,path", [("GET", "/oauth/authorize/gw1"), ("DELETE", "/oauth/tokens/gw1")])
def test_other_permissions_are_not(middleware, method, path):
    assert middleware._check_permission_restrictions(path, method, [Permissions.TOOLS_READ]) is False


def test_neighbours_keep_their_own_rules(middleware):
    # The callback has no token; registered-client deletion still needs its admin permission.
    assert middleware._check_permission_restrictions("/oauth/registered-clients/c1", "DELETE", [Permissions.GATEWAYS_READ]) is False
    assert middleware._check_permission_restrictions("/oauth/tokens/gw1", "GET", [Permissions.GATEWAYS_READ]) is False
