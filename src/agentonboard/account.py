"""
Account mapping and automated provisioning boundaries for AgentOnboard.

Implements verify_agent_account and create_agent_account per ADR 0002 and
docs/decisions/0007-agents-can-create-partner-accounts.md.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from agentonboard.codes import AccountErrorCode
from agentonboard.verify import (
    DEFAULT_CLOCK_TOLERANCE_SECONDS,
    verify_agent_token,
    verify_agent_token_async,
)

TUser = TypeVar("TUser")


@dataclass(slots=True, frozen=True)
class AgentIdentity:
    """The verified identity, and the only thing that crosses into your resolver/creator."""

    email: str


def normalize_email(email: str) -> str:
    """Normalizes an email address for database lookups by trimming whitespace and converting to lowercase."""
    if not email or not isinstance(email, str):
        return ""
    return email.strip().lower()


@dataclass(slots=True, frozen=True)
class AccountOutcome(Generic[TUser]):
    ok: bool
    email: str | None = None
    user: TUser | None = None
    created: bool = False
    code: AccountErrorCode | None = None
    error: str | None = None


AccountResolver = Callable[[AgentIdentity], TUser | None]
AccountCreator = Callable[[AgentIdentity], TUser]
AsyncAccountResolver = Callable[[AgentIdentity], Awaitable[TUser | None] | TUser | None]
AsyncAccountCreator = Callable[[AgentIdentity], Awaitable[TUser] | TUser]


def verify_agent_account(
    token: str,
    *,
    audience: str,
    resolver: AccountResolver[TUser],
    issuer: str | None = None,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
    clock_tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
) -> AccountOutcome[TUser]:
    """
    Verifies an agent session token, then maps the verified email to your own user.
    Never creates an account. If no account exists, returns ACCOUNT_REQUIRED.
    """
    verify_result = verify_agent_token(
        token=token,
        audience=audience,
        issuer=issuer,
        jwks_url=jwks_url,
        jwks=jwks,
        fetch_jwks=fetch_jwks,
        clock_tolerance_seconds=clock_tolerance_seconds,
    )

    if not verify_result.ok:
        return AccountOutcome(
            ok=False,
            code=verify_result.code,
            error=verify_result.error,
        )

    verified_email = verify_result.email or ""
    identity = AgentIdentity(email=verified_email)

    try:
        user = resolver(identity)
    except Exception:
        return AccountOutcome(
            ok=False,
            code="RESOLVER_ERROR",
            error="The account resolver threw. This is a fault in the resolver, not the token.",
        )

    if user is None:
        return AccountOutcome(
            ok=False,
            code="ACCOUNT_REQUIRED",
            error="This identity has no account at your service; send the human to connect their account, then retry.",
        )

    return AccountOutcome(
        ok=True,
        email=verified_email,
        user=user,
        created=False,
    )


async def verify_agent_account_async(
    token: str,
    *,
    audience: str,
    resolver: AsyncAccountResolver[TUser],
    issuer: str | None = None,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
    fetch_jwks_async: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
    clock_tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
) -> AccountOutcome[TUser]:
    """Asynchronous variant of verify_agent_account."""
    verify_result = await verify_agent_token_async(
        token=token,
        audience=audience,
        issuer=issuer,
        jwks_url=jwks_url,
        jwks=jwks,
        fetch_jwks=fetch_jwks,
        fetch_jwks_async=fetch_jwks_async,
        clock_tolerance_seconds=clock_tolerance_seconds,
    )

    if not verify_result.ok:
        return AccountOutcome(
            ok=False,
            code=verify_result.code,
            error=verify_result.error,
        )

    verified_email = verify_result.email or ""
    identity = AgentIdentity(email=verified_email)

    try:
        user_val = resolver(identity)
        if inspect.isawaitable(user_val):
            user = await user_val
        else:
            user = user_val
    except Exception:
        return AccountOutcome(
            ok=False,
            code="RESOLVER_ERROR",
            error="The account resolver threw. This is a fault in the resolver, not the token.",
        )

    if user is None:
        return AccountOutcome(
            ok=False,
            code="ACCOUNT_REQUIRED",
            error="This identity has no account at your service; send the human to connect their account, then retry.",
        )

    return AccountOutcome(
        ok=True,
        email=verified_email,
        user=user,
        created=False,
    )


def create_agent_account(
    token: str,
    *,
    audience: str,
    resolver: AccountResolver[TUser],
    creator: AccountCreator[TUser],
    issuer: str | None = None,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
    clock_tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
) -> AccountOutcome[TUser]:
    """
    Verifies an agent session token, maps the email to a user, and if no user exists,
    calls creator once to provision the account.
    """
    verify_result = verify_agent_token(
        token=token,
        audience=audience,
        issuer=issuer,
        jwks_url=jwks_url,
        jwks=jwks,
        fetch_jwks=fetch_jwks,
        clock_tolerance_seconds=clock_tolerance_seconds,
    )

    if not verify_result.ok:
        return AccountOutcome(
            ok=False,
            code=verify_result.code,
            error=verify_result.error,
        )

    verified_email = verify_result.email or ""
    identity = AgentIdentity(email=verified_email)

    try:
        user = resolver(identity)
    except Exception:
        return AccountOutcome(
            ok=False,
            code="RESOLVER_ERROR",
            error="The account resolver threw. This is a fault in the resolver, not the token.",
        )

    if user is not None:
        return AccountOutcome(
            ok=True,
            email=verified_email,
            user=user,
            created=False,
        )

    try:
        new_user = creator(identity)
    except Exception:
        return AccountOutcome(
            ok=False,
            code="RESOLVER_ERROR",
            error="The account creator threw. This is a fault in the creator, not the token.",
        )

    return AccountOutcome(
        ok=True,
        email=verified_email,
        user=new_user,
        created=True,
    )


async def create_agent_account_async(
    token: str,
    *,
    audience: str,
    resolver: AsyncAccountResolver[TUser],
    creator: AsyncAccountCreator[TUser],
    issuer: str | None = None,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
    fetch_jwks_async: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
    clock_tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
) -> AccountOutcome[TUser]:
    """Asynchronous variant of create_agent_account."""
    verify_result = await verify_agent_token_async(
        token=token,
        audience=audience,
        issuer=issuer,
        jwks_url=jwks_url,
        jwks=jwks,
        fetch_jwks=fetch_jwks,
        fetch_jwks_async=fetch_jwks_async,
        clock_tolerance_seconds=clock_tolerance_seconds,
    )

    if not verify_result.ok:
        return AccountOutcome(
            ok=False,
            code=verify_result.code,
            error=verify_result.error,
        )

    verified_email = verify_result.email or ""
    identity = AgentIdentity(email=verified_email)

    try:
        user_val = resolver(identity)
        if inspect.isawaitable(user_val):
            user = await user_val
        else:
            user = user_val
    except Exception:
        return AccountOutcome(
            ok=False,
            code="RESOLVER_ERROR",
            error="The account resolver threw. This is a fault in the resolver, not the token.",
        )

    if user is not None:
        return AccountOutcome(
            ok=True,
            email=verified_email,
            user=user,
            created=False,
        )

    try:
        new_user_val = creator(identity)
        if inspect.isawaitable(new_user_val):
            new_user = await new_user_val
        else:
            new_user = new_user_val
    except Exception:
        return AccountOutcome(
            ok=False,
            code="RESOLVER_ERROR",
            error="The account creator threw. This is a fault in the creator, not the token.",
        )

    return AccountOutcome(
        ok=True,
        email=verified_email,
        user=new_user,
        created=True,
    )
