"""
Flask decorator and helper for AgentOnboard.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from flask import g, jsonify, request

from agentonboard.account import (
    AccountCreator,
    AccountResolver,
    AgentIdentity,
    create_agent_account,
    verify_agent_account,
)
from agentonboard.codes import status_from_code
from agentonboard.verify import verify_agent_token

F = TypeVar("F", bound=Callable[..., Any])
TUser = TypeVar("TUser")


def require_agent_token(
    *,
    audience: str,
    resolver: AccountResolver[TUser] | None = None,
    creator: AccountCreator[TUser] | None = None,
    auto_create: bool = False,
    issuer: str | None = None,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """
    Flask route decorator for verifying AgentOnboard session tokens.

    Usage:
        @app.route("/protected")
        @require_agent_token(audience="notes.com")
        def protected():
            return jsonify({"user": g.agent_identity.email})
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header or not auth_header.startswith("Bearer "):
                return (
                    jsonify(
                        {
                            "code": "MALFORMED_TOKEN",
                            "error": "Missing or malformed Authorization Bearer header",
                        }
                    ),
                    401,
                )

            token = auth_header[7:].strip()

            if resolver is None:
                res = verify_agent_token(
                    token=token,
                    audience=audience,
                    issuer=issuer,
                    jwks_url=jwks_url,
                    jwks=jwks,
                )
                if not res.ok:
                    status_code = status_from_code(res.code)
                    return jsonify({"code": res.code, "error": res.error}), status_code

                identity = AgentIdentity(email=res.email or "")
                g.agent_identity = identity

                sig = inspect.signature(fn)
                if "agent_identity" in sig.parameters:
                    kwargs["agent_identity"] = identity
                return fn(*args, **kwargs)

            # Account resolution
            if auto_create and creator is not None:
                outcome = create_agent_account(
                    token=token,
                    audience=audience,
                    resolver=resolver,
                    creator=creator,
                    issuer=issuer,
                    jwks_url=jwks_url,
                    jwks=jwks,
                )
            else:
                outcome = verify_agent_account(
                    token=token,
                    audience=audience,
                    resolver=resolver,
                    issuer=issuer,
                    jwks_url=jwks_url,
                    jwks=jwks,
                )

            if not outcome.ok:
                status_code = status_from_code(outcome.code)
                return jsonify({"code": outcome.code, "error": outcome.error}), status_code

            identity = AgentIdentity(email=outcome.email or "")
            g.agent_identity = identity
            g.agent_user = outcome.user

            sig = inspect.signature(fn)
            if "agent_user" in sig.parameters:
                kwargs["agent_user"] = outcome.user
            if "agent_identity" in sig.parameters:
                kwargs["agent_identity"] = identity

            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
