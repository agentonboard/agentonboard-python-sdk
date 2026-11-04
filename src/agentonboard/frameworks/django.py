"""
Django view decorator for AgentOnboard.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from django.http import HttpRequest, JsonResponse

from agentonboard.account import (
    AccountCreator,
    AccountResolver,
    AgentIdentity,
    AsyncAccountCreator,
    AsyncAccountResolver,
    create_agent_account,
    create_agent_account_async,
    verify_agent_account,
    verify_agent_account_async,
)
from agentonboard.codes import status_from_code
from agentonboard.verify import verify_agent_token, verify_agent_token_async

F = TypeVar("F", bound=Callable[..., Any])
TUser = TypeVar("TUser")


def _extract_bearer(request: HttpRequest) -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header[7:].strip()
    return token or None


def require_agent_token(
    *,
    audience: str,
    resolver: AccountResolver[TUser] | AsyncAccountResolver[TUser] | None = None,
    creator: AccountCreator[TUser] | AsyncAccountCreator[TUser] | None = None,
    auto_create: bool = False,
    issuer: str | None = None,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """
    Django view decorator for verifying AgentOnboard session tokens.
    Supports both synchronous and asynchronous Django views.

    Usage:
        @require_agent_token(audience="notes.com", resolver=find_user)
        def notes_view(request):
            return JsonResponse({"user": request.agent_user.id})
    """

    def decorator(fn: F) -> F:
        sig = inspect.signature(fn)
        wants_identity = "agent_identity" in sig.parameters
        wants_user = "agent_user" in sig.parameters

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
                token = _extract_bearer(request)
                if not token:
                    return JsonResponse(
                        {
                            "code": "MALFORMED_TOKEN",
                            "error": "Missing or malformed Authorization Bearer header",
                        },
                        status=401,
                    )

                if resolver is None:
                    res = await verify_agent_token_async(
                        token=token,
                        audience=audience,
                        issuer=issuer,
                        jwks_url=jwks_url,
                        jwks=jwks,
                    )
                    if not res.ok:
                        return JsonResponse(
                            {"code": res.code, "error": res.error},
                            status=status_from_code(res.code),
                        )

                    identity = AgentIdentity(email=res.email or "")
                    request.agent_identity = identity  # type: ignore[attr-defined]
                    if wants_identity:
                        kwargs["agent_identity"] = identity
                    return await fn(request, *args, **kwargs)

                if auto_create and creator is not None:
                    outcome = await create_agent_account_async(
                        token=token,
                        audience=audience,
                        resolver=resolver,  # type: ignore[arg-type]
                        creator=creator,  # type: ignore[arg-type]
                        issuer=issuer,
                        jwks_url=jwks_url,
                        jwks=jwks,
                    )
                else:
                    outcome = await verify_agent_account_async(
                        token=token,
                        audience=audience,
                        resolver=resolver,  # type: ignore[arg-type]
                        issuer=issuer,
                        jwks_url=jwks_url,
                        jwks=jwks,
                    )

                if not outcome.ok:
                    return JsonResponse(
                        {"code": outcome.code, "error": outcome.error},
                        status=status_from_code(outcome.code),
                    )

                identity = AgentIdentity(email=outcome.email or "")
                request.agent_identity = identity  # type: ignore[attr-defined]
                request.agent_user = outcome.user  # type: ignore[attr-defined]
                if wants_user:
                    kwargs["agent_user"] = outcome.user
                if wants_identity:
                    kwargs["agent_identity"] = identity

                return await fn(request, *args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            token = _extract_bearer(request)
            if not token:
                return JsonResponse(
                    {
                        "code": "MALFORMED_TOKEN",
                        "error": "Missing or malformed Authorization Bearer header",
                    },
                    status=401,
                )

            if resolver is None:
                res = verify_agent_token(
                    token=token,
                    audience=audience,
                    issuer=issuer,
                    jwks_url=jwks_url,
                    jwks=jwks,
                )
                if not res.ok:
                    return JsonResponse(
                        {"code": res.code, "error": res.error},
                        status=status_from_code(res.code),
                    )

                identity = AgentIdentity(email=res.email or "")
                request.agent_identity = identity  # type: ignore[attr-defined]
                if wants_identity:
                    kwargs["agent_identity"] = identity
                return fn(request, *args, **kwargs)

            if auto_create and creator is not None:
                outcome = create_agent_account(
                    token=token,
                    audience=audience,
                    resolver=resolver,  # type: ignore[arg-type]
                    creator=creator,  # type: ignore[arg-type]
                    issuer=issuer,
                    jwks_url=jwks_url,
                    jwks=jwks,
                )
            else:
                outcome = verify_agent_account(
                    token=token,
                    audience=audience,
                    resolver=resolver,  # type: ignore[arg-type]
                    issuer=issuer,
                    jwks_url=jwks_url,
                    jwks=jwks,
                )

            if not outcome.ok:
                return JsonResponse(
                    {"code": outcome.code, "error": outcome.error},
                    status=status_from_code(outcome.code),
                )

            identity = AgentIdentity(email=outcome.email or "")
            request.agent_identity = identity  # type: ignore[attr-defined]
            request.agent_user = outcome.user  # type: ignore[attr-defined]
            if wants_user:
                kwargs["agent_user"] = outcome.user
            if wants_identity:
                kwargs["agent_identity"] = identity

            return fn(request, *args, **kwargs)

        return sync_wrapper  # type: ignore[return-value]

    return decorator
