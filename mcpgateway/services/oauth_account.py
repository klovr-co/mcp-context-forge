# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/services/oauth_account.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Whose account a caller's saved OAuth sign-in is.

The answer comes from the authorization server's own UserInfo endpoint (OpenID
Connect Core 1.0, section 5.3), found in its published metadata (RFC 8414, or
OpenID Connect Discovery). The caller's access token goes only to an endpoint on
the issuer's own origin, and it never leaves the gateway in the answer.

Nothing is stored. An answer is kept in memory for the sign-in it was read with
(its ``updated_at``), so a renewed or replaced sign-in is asked again.
"""

# Standard
from collections import OrderedDict
import logging
from time import monotonic
from typing import Any, Optional, TYPE_CHECKING
import unicodedata

# Third-Party
import httpx

# First-Party
from mcpgateway.config import get_settings
from mcpgateway.services.dcr_service import DcrError, DcrService
from mcpgateway.services.http_client_service import get_isolated_http_client

if TYPE_CHECKING:
    # First-Party
    from mcpgateway.services.token_storage_service import TokenStorageService

logger = logging.getLogger(__name__)

_KEPT = 1024
_FAILED_SECONDS = 60.0
_ANSWERED_SECONDS = 24 * 3600.0
_answers: "OrderedDict[tuple, tuple[float, Optional[dict[str, str]]]]" = OrderedDict()


class _Unanswered(Exception):
    """The server could not be asked this time: unreachable, refused, or an unreadable reply."""


def _claim(value: Any, limit: int) -> Optional[str]:
    """A claim as a short printable string, or ``None``.

    Args:
        value: The claim from the UserInfo answer.
        limit: Longest accepted length.

    Returns:
        The trimmed string, or ``None`` when it is not a usable string.

    Examples:
        >>> _claim(" a@b.co ", 254)
        'a@b.co'
        >>> _claim("a\\nb", 254) is None
        True
        >>> _claim(12, 254) is None
        True
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > limit or any(unicodedata.category(c).startswith("C") for c in value):
        return None
    return value


def _account(claims: Any) -> Optional[dict[str, str]]:
    """The account from a UserInfo answer: its ``sub`` and, when given, its ``email``.

    Args:
        claims: The decoded UserInfo answer.

    Returns:
        ``{"sub": ..., "email": ...}`` (``email`` only when given), or ``None`` without a ``sub``.

    Examples:
        >>> _account({"sub": "u1", "email": "a@b.co", "name": "A"})
        {'sub': 'u1', 'email': 'a@b.co'}
        >>> _account({"sub": "u1", "email": "not an email"})
        {'sub': 'u1'}
        >>> _account({"email": "a@b.co"}) is None
        True
    """
    if not isinstance(claims, dict):
        return None
    sub = _claim(claims.get("sub"), 255)
    if not sub:
        return None
    account = {"sub": sub}
    email = _claim(claims.get("email"), 254)
    if email and "@" in email and " " not in email:
        account["email"] = email
    return account


async def _ask(issuer: str, access_token: str) -> Optional[dict[str, str]]:
    """Ask the issuer's UserInfo endpoint whose token this is.

    Args:
        issuer: The authorization server's issuer.
        access_token: The caller's access token for this server.

    Returns:
        The account, or ``None`` when the server publishes no UserInfo endpoint or names no account.

    Raises:
        _Unanswered: When the server could not be asked.
    """
    dcr = DcrService()
    try:
        metadata = await dcr.discover_as_metadata(issuer)
    except (DcrError, httpx.HTTPError, ValueError) as error:
        raise _Unanswered(f"metadata: {error}") from error
    endpoint = metadata.get("userinfo_endpoint")
    if not isinstance(endpoint, str) or not endpoint:
        return None
    try:
        # Same origin as the issuer, allowed by the URL policy, dialled at the address checked.
        target = await dcr._prepare_pinned_request(endpoint, (metadata.get("issuer") or issuer).rstrip("/"), "userinfo_endpoint")  # pylint: disable=protected-access
    except DcrError as error:
        raise _Unanswered(f"userinfo_endpoint refused: {error}") from error
    try:
        async with get_isolated_http_client(follow_redirects=False) as client:
            response = await client.get(
                target.url,
                timeout=float(get_settings().oauth_request_timeout),
                follow_redirects=False,
                headers={**target.headers, "Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                extensions=target.extensions,
            )
    except httpx.HTTPError as error:
        raise _Unanswered(f"userinfo: {type(error).__name__}") from error
    if response.status_code != 200:
        raise _Unanswered(f"userinfo answered {response.status_code}")
    try:
        return _account(response.json())
    except ValueError as error:
        raise _Unanswered("userinfo answered something other than JSON") from error


async def signed_in_account(token_storage: "TokenStorageService", gateway_id: str, oauth_config: Optional[dict], app_user_email: str, updated_at: Optional[str]) -> Optional[dict[str, str]]:
    """Whose account the caller's saved sign-in to a gateway is.

    Only a token that is valid now is sent; an expired one is not renewed here. The answer is
    dropped when the saved sign-in changed while it was asked.

    Args:
        token_storage: The caller's token storage.
        gateway_id: The gateway.
        oauth_config: The gateway's OAuth configuration; its ``issuer`` names the server to ask.
        app_user_email: The caller.
        updated_at: When the caller's saved sign-in was last written, as the status reports it.

    Returns:
        ``{"sub": ..., "email": ...}`` (``email`` only when the server gives one), or ``None``.
    """
    issuer = (oauth_config or {}).get("issuer")
    if not isinstance(issuer, str) or not issuer or not updated_at:
        return None
    key = (gateway_id, app_user_email.lower(), updated_at, issuer)
    kept = _answers.get(key)
    if kept and kept[0] > monotonic():
        return kept[1]
    token = await token_storage.read_validation_token(gateway_id, app_user_email)
    if token is None or token.status != "valid" or not token.access_token:
        return None
    try:
        answer, seconds = await _ask(issuer, token.access_token), _ANSWERED_SECONDS
    except _Unanswered as error:
        logger.info("Couldn't ask gateway %s's authorization server whose sign-in this is: %s", gateway_id, error)
        answer, seconds = None, _FAILED_SECONDS
    info = await token_storage.get_token_info(gateway_id, app_user_email)
    if not info or info.get("updated_at") != updated_at:
        return None                                     # signed in again meanwhile: the answer may be the old login's
    _keep(key, answer, seconds)
    return answer


def _keep(key: tuple, answer: Optional[dict[str, str]], seconds: float) -> None:
    """Keep an answer for one saved sign-in, dropping the oldest past ``_KEPT`` answers.

    Args:
        key: Gateway, caller, sign-in version and issuer.
        answer: The account, or ``None``.
        seconds: How long it stands.
    """
    _answers[key] = (monotonic() + seconds, answer)
    _answers.move_to_end(key)
    while len(_answers) > _KEPT:
        _answers.popitem(last=False)
