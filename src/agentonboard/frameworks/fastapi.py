"""
FastAPI security dependency for AgentOnboard.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from fastapi import HTTPException, Request, status
from fastapi.openapi.models import HTTPBearer as HTTPBearerModel
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.security.base import SecurityBase

from agentonboard.account import (
    AgentIdentity,
    AsyncAccountCreator,
    AsyncAccountResolver,
    create_agent_account_async,
    verify_agent_account_async,
)
from agentonboard.codes import status_from_code
from agentonboard.verify import verify_agent_token_async

TUser = TypeVar("TUser")


class AgentBearerAuth(SecurityBase, Generic[TUser]):
    """
    FastAPI dependency for verifying AgentOnboard session tokens and resolving accounts.

    Usage:
        auth = AgentBearerAuth(audience="notes.com")

        @app.get("/items")
        async def read_items(identity: AgentIdentity = Depends(auth)):
            return {"user": identity.email}
    """

    def __init__(
        self,
        *,
        audience: str,
        resolver: AsyncAccountResolver[TUser] | None = None,
        creator: AsyncAccountCreator[TUser] | None = None,
        auto_create: bool = False,
        issuer: str | None = None,
        jwks_url: str | None = None,
        jwks: dict[str, Any] | None = None,
        auto_error: bool = True,
    ) -> None:
        self.model = HTTPBearerModel()
        self.scheme_name = self.__class__.__name__
        self.bearer = HTTPBearer(auto_error=auto_error)
        self.audience = audience
        self.resolver = resolver
        self.creator = creator
        self.auto_create = auto_create
        self.issuer = issuer
        self.jwks_url = jwks_url
        self.jwks = jwks

    async def __call__(
        self, request: Request
    ) -> AgentIdentity | TUser:
        credentials: HTTPAuthorizationCredentials | None = await self.bearer(request)
        if not credentials or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "MALFORMED_TOKEN", "error": "Missing authorization bearer token"},
            )

        token = credentials.credentials

        if self.resolver is None:
            # Token verification only
            result = await verify_agent_token_async(
                token=token,
                audience=self.audience,
                issuer=self.issuer,
                jwks_url=self.jwks_url,
                jwks=self.jwks,
            )
            if not result.ok:
                http_status = status_from_code(result.code)
                raise HTTPException(
                    status_code=http_status,
                    detail={"code": result.code, "error": result.error},
                )
            return AgentIdentity(email=result.email or "")

        # Account resolution / provisioning
        if self.auto_create and self.creator is not None:
            outcome = await create_agent_account_async(
                token=token,
                audience=self.audience,
                resolver=self.resolver,
                creator=self.creator,
                issuer=self.issuer,
                jwks_url=self.jwks_url,
                jwks=self.jwks,
            )
        else:
            outcome = await verify_agent_account_async(
                token=token,
                audience=self.audience,
                resolver=self.resolver,
                issuer=self.issuer,
                jwks_url=self.jwks_url,
                jwks=self.jwks,
            )

        if not outcome.ok:
            http_status = status_from_code(outcome.code)
            raise HTTPException(
                status_code=http_status,
                detail={"code": outcome.code, "error": outcome.error},
            )

        return outcome.user  # type: ignore[return-value]
