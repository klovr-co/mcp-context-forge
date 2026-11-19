# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/services/oauth_account.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Whose account a caller's saved OAuth sign-in is.

The answer comes from the authorization server's own UserInfo endpoint (OpenID
Connect Core 1.0, section 5.3), found in its published metadata (RFC 8414, or
OpenID Connect Discovery).

The caller's access token goes only to the issuer that issued it: the issuer the
saved sign-in recorded when it was made (``learned_iss``, kept only when it
matched the gateway's issuer then), and only while the gateway still names that
issuer. A sign-in that recorded no issuer, or a gateway whose issuer was changed
since, sends nothing. Every request is HTTPS with certificate verification, on the
issuer's own origin, pinned to the address checked, within one total deadline,
and reads at most a few kilobytes. The token never leaves the gateway in the answer.

Nothing is stored. An answer is kept in memory for the sign-in it was read with
(its ``updated_at``), so a renewed or replaced sign-in is asked again.
"""

# Standard
import asyncio
from collections import OrderedDict
import logging
from time import monotonic
from typing import Any, Optional, TYPE_CHECKING
import unicodedata
from urllib.parse import urlsplit

# Third-Party
import httpx

# First-Party
from mcpgateway.services.dcr_service import DcrError, DcrService
from mcpgateway.services.http_client_service import get_isolated_http_client

if TYPE_CHECKING:
    # First-Party
    from mcpgateway.services.token_storage_service import TokenStorageService

logger = logging.getLogger(__name__)

_KEPT = 1024
_FAILED_SECONDS = 60.0
_ANSWERED_SECONDS = 24 * 3600.0
_DEADLINE_SECONDS = 5.0  # the whole lookup: discovery and UserInfo
_METADATA_BYTES = 64 * 1024
_USERINFO_BYTES = 16 * 1024
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
        >>> _account({"sub": "u1", "email": "a@b.co", "email_verified": False})
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
    if email and "@" in email and " " not in email and claims.get("email_verified") is not False:
        account["email"] = email
    return account


def _https_issuer(issuer: Any) -> Optional[str]:
    """The issuer without a trailing slash, when it is an HTTPS URL with a host and no credentials.

    Args:
        issuer: An issuer identifier.

    Returns:
        The normalised issuer, or ``None``.

    Examples:
        >>> _https_issuer("https://as.example.com/auth/v1/")
        'https://as.example.com/auth/v1'
        >>> _https_issuer("http://as.example.com") is None
        True
        >>> _https_issuer("https://u:p@as.example.com") is None
        True
    """
    if not isinstance(issuer, str):
        return None
    parts = urlsplit(issuer.strip())
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        return None
    return issuer.strip().rstrip("/")


async def _get_json(dcr: DcrService, url: str, issuer: str, field: str, limit: int, headers: Optional[dict[str, str]] = None) -> Optional[Any]:
    """GET a JSON document on the issuer's origin over verified HTTPS, reading at most ``limit`` bytes.

    Args:
        dcr: Supplies the URL policy and address pinning.
        url: The document's URL.
        issuer: The issuer whose origin the URL must share.
        field: What the URL is, for the policy's refusal.
        limit: Most bytes read.
        headers: Extra request headers.

    Returns:
        The decoded document, or ``None`` when the server answered 404.

    Raises:
        _Unanswered: On a refused URL, a transport error, another status, too large or unreadable a body.
    """
    if urlsplit(url).scheme != "https":
        raise _Unanswered(f"{field} is not https")
    try:
        target = await dcr._prepare_pinned_request(url, issuer, field)  # pylint: disable=protected-access
    except DcrError as error:
        raise _Unanswered(f"{field} refused") from error
    try:
        async with get_isolated_http_client(follow_redirects=False, verify=True) as client:
            async with client.stream("GET", target.url, follow_redirects=False, headers={**target.headers, **(headers or {}), "Accept": "application/json"}, extensions=target.extensions) as response:
                if response.status_code == 404:
                    return None
                if response.status_code != 200:
                    raise _Unanswered(f"{field} answered {response.status_code}")
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > limit:
                    raise _Unanswered(f"{field} answer too large")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise _Unanswered(f"{field} answer too large")
    except httpx.HTTPError as error:
        raise _Unanswered(f"{field}: {type(error).__name__}") from error
    try:
        return httpx.Response(200, content=bytes(body)).json()
    except ValueError as error:
        raise _Unanswered(f"{field} answered something other than JSON") from error


async def _userinfo_endpoint(dcr: DcrService, issuer: str) -> Optional[str]:
    """The issuer's published UserInfo endpoint: RFC 8414 metadata first, then OpenID Connect Discovery.

    Args:
        dcr: Supplies the URL policy and address pinning.
        issuer: The normalised HTTPS issuer.

    Returns:
        The endpoint, or ``None`` when the issuer publishes none.

    Raises:
        _Unanswered: When the metadata could not be read, or names another issuer.
    """
    parts = urlsplit(issuer)
    for url in (f"https://{parts.netloc}/.well-known/oauth-authorization-server{parts.path}", f"{issuer}/.well-known/openid-configuration"):
        metadata = await _get_json(dcr, url, issuer, "AS metadata discovery URL", _METADATA_BYTES)
        if metadata is None:
            continue
        if not isinstance(metadata, dict) or str(metadata.get("issuer") or "").rstrip("/") != issuer:
            raise _Unanswered("metadata names another issuer")
        endpoint = metadata.get("userinfo_endpoint")
        return endpoint if isinstance(endpoint, str) and endpoint else None
    return None


async def _ask(issuer: str, access_token: str) -> Optional[dict[str, str]]:
    """Ask the issuer's UserInfo endpoint whose token this is.

    Args:
        issuer: The normalised HTTPS issuer that issued the token.
        access_token: The caller's access token for this server.

    Returns:
        The account, or ``None`` when the server publishes no UserInfo endpoint or names no account.

    Raises:
        _Unanswered: When the server could not be asked.
    """
    dcr = DcrService()
    endpoint = await _userinfo_endpoint(dcr, issuer)
    if not endpoint:
        return None
    claims = await _get_json(dcr, endpoint, issuer, "userinfo_endpoint", _USERINFO_BYTES, {"Authorization": f"Bearer {access_token}"})
    return _account(claims) if claims is not None else None


async def signed_in_account(token_storage: "TokenStorageService", gateway_id: str, oauth_config: Optional[dict], app_user_email: str, updated_at: Optional[str]) -> Optional[dict[str, str]]:
    """Whose account the caller's saved sign-in to a gateway is.

    Only a token that is valid now is sent, and only to the issuer the saved sign-in recorded, while
    the gateway still names it; an expired token is not renewed here. A kept answer is returned only
    while the saved sign-in is still the one it was read with, and the answer is dropped when the
    saved sign-in changed while it was asked.

    Args:
        token_storage: The caller's token storage.
        gateway_id: The gateway.
        oauth_config: The gateway's OAuth configuration; its ``issuer`` must be the one the sign-in recorded.
        app_user_email: The caller.
        updated_at: When the caller's saved sign-in was last written, as the status reports it.

    Returns:
        ``{"sub": ..., "email": ...}`` (``email`` only when the server gives one), or ``None``.
    """
    issuer = _https_issuer((oauth_config or {}).get("issuer"))
    if not issuer or not updated_at:
        return None
    _aud, learned_iss = await token_storage.get_user_learned_audience(gateway_id, app_user_email)
    if _https_issuer(learned_iss) != issuer:
        return None                                     # issued by another issuer, or it wasn't recorded: send nothing
    token = await token_storage.read_validation_token(gateway_id, app_user_email)
    if token is None or token.status != "valid" or not token.access_token:
        return None
    info = await token_storage.get_token_info(gateway_id, app_user_email)
    if not info or info.get("updated_at") != updated_at:
        return None                                     # not the sign-in the caller's status named
    team = getattr(token_storage, "_get_team_id", lambda *_: None)(gateway_id, app_user_email)
    key = (gateway_id, app_user_email.lower(), team, updated_at, issuer)
    kept = _answers.get(key)
    if kept and kept[0] > monotonic():
        return kept[1]
    try:
        answer, seconds = await asyncio.wait_for(_ask(issuer, token.access_token), _DEADLINE_SECONDS), _ANSWERED_SECONDS
    except (_Unanswered, asyncio.TimeoutError) as error:
        logger.info("Couldn't ask gateway %s's authorization server whose sign-in this is: %s", gateway_id, error if isinstance(error, _Unanswered) else "deadline passed")
        answer, seconds = None, _FAILED_SECONDS
    info = await token_storage.get_token_info(gateway_id, app_user_email)
    if not info or info.get("updated_at") != updated_at:
        return None                                     # signed in again meanwhile: the answer may be the old login's
    _keep(key, answer, seconds)
    return answer


def _keep(key: tuple, answer: Optional[dict[str, str]], seconds: float) -> None:
    """Keep an answer for one saved sign-in, dropping the oldest past ``_KEPT`` answers.

    Args:
        key: Gateway, caller, team, sign-in version and issuer.
        answer: The account, or ``None``.
        seconds: How long it stands.
    """
    _answers[key] = (monotonic() + seconds, answer)
    _answers.move_to_end(key)
    while len(_answers) > _KEPT:
        _answers.popitem(last=False)
