"""
Token verification module for AgentOnboard ephemeral session tokens.
"""

from __future__ import annotations

import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlsplit

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    MissingRequiredClaimError,
    PyJWTError,
)

from agentonboard.codes import VerifyErrorCode
from agentonboard.keys import (
    KeyNotFoundError,
    KeySourceCache,
    KeySourceUnavailableError,
    get_cached_key_source,
)

ALGORITHMS = ["RS256"]
REQUIRED_CLAIMS = ["exp", "jti", "sub", "email"]
DEFAULT_CLOCK_TOLERANCE_SECONDS = 5


@dataclass(slots=True, frozen=True)
class VerifyAgentTokenResult:
    ok: bool
    email: str | None = None
    sub: str | None = None
    user_id: str | None = None  # Alias for sub
    expires_at: int | None = None
    jti: str | None = None
    audience: str | None = None
    code: VerifyErrorCode | None = None
    error: str | None = None


def normalize_audience(input_str: str) -> str:
    """
    Normalizes audience input into a clean hostname.
    (e.g. "https://api.notes.com/v1" -> "api.notes.com")
    """
    if not input_str or not isinstance(input_str, str):
        return ""
    raw = input_str.strip()
    while raw.endswith("/"):
        raw = raw[:-1]
    if not raw:
        return ""
    target = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlsplit(target)
        host = (parsed.hostname or "").lower()
        if not host:
            return ""
        if host in ("localhost", "127.0.0.1") and parsed.port:
            return f"{host}:{parsed.port}"
        return host
    except Exception:
        return ""


def resolve_issuer(issuer: str | None = None) -> str:
    return issuer or os.getenv("AON_ISSUER") or "https://agentonboard.xyz"


class Verifier:
    """Configurable Verifier instance holding its own key cache."""

    def __init__(self, cache: KeySourceCache | None = None) -> None:
        self.cache = cache or KeySourceCache()

    def verify(
        self,
        token: str,
        *,
        audience: str,
        issuer: str | None = None,
        jwks_url: str | None = None,
        jwks: dict[str, Any] | None = None,
        fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
        clock_tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
    ) -> VerifyAgentTokenResult:
        if not token or not isinstance(token, str):
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error="Missing or empty token",
            )

        if not audience or not isinstance(audience, str):
            return VerifyAgentTokenResult(
                ok=False,
                code="CONFIG_ERROR",
                error="Missing expected audience for verification",
            )

        if not isinstance(clock_tolerance_seconds, (int, float)) or clock_tolerance_seconds < 0:
            return VerifyAgentTokenResult(
                ok=False,
                code="CONFIG_ERROR",
                error="clockToleranceSeconds must be a non-negative number of seconds",
            )

        clean_token = re.sub(r"^Bearer\s+", "", token.strip(), flags=re.IGNORECASE).strip()
        normalized_aud = normalize_audience(audience)
        if not normalized_aud:
            return VerifyAgentTokenResult(
                ok=False,
                code="CONFIG_ERROR",
                error=f'Audience does not normalize to a hostname: "{audience}"',
            )

        resolved_iss = resolve_issuer(issuer)
        resolved_jwks_url = jwks_url or f"{resolved_iss.rstrip('/')}/.well-known/jwks.json"

        try:
            parsed_jwks_url = urlparse(resolved_jwks_url)
            if not parsed_jwks_url.scheme or not parsed_jwks_url.netloc:
                return VerifyAgentTokenResult(
                    ok=False,
                    code="CONFIG_ERROR",
                    error=f'JWKS URL is not a valid URL: "{resolved_jwks_url}"',
                )
        except Exception:
            return VerifyAgentTokenResult(
                ok=False,
                code="CONFIG_ERROR",
                error=f'JWKS URL is not a valid URL: "{resolved_jwks_url}"',
            )

        try:
            header = jwt.get_unverified_header(clean_token)
        except Exception:
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error="Token is not a readable compact JWS",
            )

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            return VerifyAgentTokenResult(
                ok=False,
                code="UNKNOWN_KEY",
                error="Token header carries no kid, so no signing key can be selected",
            )

        alg = header.get("alg")
        if alg not in ALGORITHMS:
            return VerifyAgentTokenResult(
                ok=False,
                code="INVALID_SIGNATURE",
                error="Token uses a signing algorithm this SDK does not accept",
            )

        try:
            key_source = get_cached_key_source(
                url=resolved_jwks_url,
                jwks=jwks,
                fetch_jwks=fetch_jwks,
                cache=self.cache,
            )
            signing_key = key_source.get_key(kid)
        except KeyNotFoundError:
            return VerifyAgentTokenResult(
                ok=False,
                code="UNKNOWN_KEY",
                error=(
                    "Token kid matched no key in the key set this SDK could obtain. The set may be "
                    "out of date when the key endpoint is unreachable, so this does not mean the "
                    "token is forged."
                ),
            )
        except KeySourceUnavailableError as err:
            return VerifyAgentTokenResult(
                ok=False,
                code="KEY_SOURCE_UNAVAILABLE",
                error=f"Could not obtain a signing key: {err}",
            )

        try:
            payload = jwt.decode(
                clean_token,
                key=signing_key,
                algorithms=ALGORITHMS,
                audience=normalized_aud,
                issuer=resolved_iss,
                leeway=clock_tolerance_seconds,
                options={"require": REQUIRED_CLAIMS},
            )
        except ExpiredSignatureError:
            return VerifyAgentTokenResult(
                ok=False,
                code="EXPIRED",
                error="Agent session token has expired (5-minute lifetime exceeded)",
            )
        except InvalidAudienceError:
            return VerifyAgentTokenResult(
                ok=False,
                code="AUDIENCE_MISMATCH",
                error="Audience mismatch: token was minted for different domain",
            )
        except InvalidIssuerError:
            return VerifyAgentTokenResult(
                ok=False,
                code="ISSUER_MISMATCH",
                error="Issuer mismatch",
            )
        except InvalidSignatureError:
            return VerifyAgentTokenResult(
                ok=False,
                code="INVALID_SIGNATURE",
                error="Invalid cryptographic signature",
            )
        except InvalidAlgorithmError:
            return VerifyAgentTokenResult(
                ok=False,
                code="INVALID_SIGNATURE",
                error="Token uses a signing algorithm this SDK does not accept",
            )
        except MissingRequiredClaimError as err:
            claim_name = getattr(err, "claim", "")
            if not claim_name:
                # Parse claim from message "missing required claim: xxx"
                match = re.search(r"claim\s*[:\s]\s*(\w+)", str(err), re.IGNORECASE)
                if match:
                    claim_name = match.group(1).lower()

            if claim_name == "email":
                return VerifyAgentTokenResult(
                    ok=False,
                    code="MISSING_EMAIL",
                    error="Token carries no usable email claim",
                )
            if claim_name == "aud":
                return VerifyAgentTokenResult(
                    ok=False,
                    code="AUDIENCE_MISMATCH",
                    error="Audience mismatch: token was minted for different domain",
                )
            if claim_name == "iss":
                return VerifyAgentTokenResult(
                    ok=False,
                    code="ISSUER_MISMATCH",
                    error="Issuer mismatch",
                )
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error=f"Missing required claim: {claim_name or err}",
            )
        except DecodeError as err:
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error=str(err),
            )
        except PyJWTError as err:
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error=str(err),
            )

        email = payload.get("email")
        if not isinstance(email, str) or not email:
            return VerifyAgentTokenResult(
                ok=False,
                code="MISSING_EMAIL",
                error="Token carries no usable email claim",
            )

        sub = payload.get("sub")
        sub_str = str(sub) if sub is not None else email
        exp = payload.get("exp")
        exp_int = int(exp) if isinstance(exp, (int, float)) else 0
        jti = payload.get("jti")
        jti_str = str(jti) if jti is not None else ""

        return VerifyAgentTokenResult(
            ok=True,
            email=email,
            sub=sub_str,
            user_id=sub_str,
            expires_at=exp_int,
            jti=jti_str,
            audience=normalized_aud,
        )

    async def verify_async(
        self,
        token: str,
        *,
        audience: str,
        issuer: str | None = None,
        jwks_url: str | None = None,
        jwks: dict[str, Any] | None = None,
        fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
        fetch_jwks_async: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
        clock_tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
    ) -> VerifyAgentTokenResult:
        if not token or not isinstance(token, str):
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error="Missing or empty token",
            )

        if not audience or not isinstance(audience, str):
            return VerifyAgentTokenResult(
                ok=False,
                code="CONFIG_ERROR",
                error="Missing expected audience for verification",
            )

        if not isinstance(clock_tolerance_seconds, (int, float)) or clock_tolerance_seconds < 0:
            return VerifyAgentTokenResult(
                ok=False,
                code="CONFIG_ERROR",
                error="clockToleranceSeconds must be a non-negative number of seconds",
            )

        clean_token = re.sub(r"^Bearer\s+", "", token.strip(), flags=re.IGNORECASE).strip()
        normalized_aud = normalize_audience(audience)
        if not normalized_aud:
            return VerifyAgentTokenResult(
                ok=False,
                code="CONFIG_ERROR",
                error=f'Audience does not normalize to a hostname: "{audience}"',
            )

        resolved_iss = resolve_issuer(issuer)
        resolved_jwks_url = jwks_url or f"{resolved_iss.rstrip('/')}/.well-known/jwks.json"

        try:
            parsed_jwks_url = urlparse(resolved_jwks_url)
            if not parsed_jwks_url.scheme or not parsed_jwks_url.netloc:
                return VerifyAgentTokenResult(
                    ok=False,
                    code="CONFIG_ERROR",
                    error=f'JWKS URL is not a valid URL: "{resolved_jwks_url}"',
                )
        except Exception:
            return VerifyAgentTokenResult(
                ok=False,
                code="CONFIG_ERROR",
                error=f'JWKS URL is not a valid URL: "{resolved_jwks_url}"',
            )

        try:
            header = jwt.get_unverified_header(clean_token)
        except Exception:
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error="Token is not a readable compact JWS",
            )

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            return VerifyAgentTokenResult(
                ok=False,
                code="UNKNOWN_KEY",
                error="Token header carries no kid, so no signing key can be selected",
            )

        alg = header.get("alg")
        if alg not in ALGORITHMS:
            return VerifyAgentTokenResult(
                ok=False,
                code="INVALID_SIGNATURE",
                error="Token uses a signing algorithm this SDK does not accept",
            )

        try:
            key_source = get_cached_key_source(
                url=resolved_jwks_url,
                jwks=jwks,
                fetch_jwks=fetch_jwks,
                fetch_jwks_async=fetch_jwks_async,
                cache=self.cache,
            )
            signing_key = await key_source.get_key_async(kid)
        except KeyNotFoundError:
            return VerifyAgentTokenResult(
                ok=False,
                code="UNKNOWN_KEY",
                error=(
                    "Token kid matched no key in the key set this SDK could obtain. The set may be "
                    "out of date when the key endpoint is unreachable, so this does not mean the "
                    "token is forged."
                ),
            )
        except KeySourceUnavailableError as err:
            return VerifyAgentTokenResult(
                ok=False,
                code="KEY_SOURCE_UNAVAILABLE",
                error=f"Could not obtain a signing key: {err}",
            )

        try:
            payload = jwt.decode(
                clean_token,
                key=signing_key,
                algorithms=ALGORITHMS,
                audience=normalized_aud,
                issuer=resolved_iss,
                leeway=clock_tolerance_seconds,
                options={"require": REQUIRED_CLAIMS},
            )
        except ExpiredSignatureError:
            return VerifyAgentTokenResult(
                ok=False,
                code="EXPIRED",
                error="Agent session token has expired (5-minute lifetime exceeded)",
            )
        except InvalidAudienceError:
            return VerifyAgentTokenResult(
                ok=False,
                code="AUDIENCE_MISMATCH",
                error="Audience mismatch: token was minted for different domain",
            )
        except InvalidIssuerError:
            return VerifyAgentTokenResult(
                ok=False,
                code="ISSUER_MISMATCH",
                error="Issuer mismatch",
            )
        except InvalidSignatureError:
            return VerifyAgentTokenResult(
                ok=False,
                code="INVALID_SIGNATURE",
                error="Invalid cryptographic signature",
            )
        except InvalidAlgorithmError:
            return VerifyAgentTokenResult(
                ok=False,
                code="INVALID_SIGNATURE",
                error="Token uses a signing algorithm this SDK does not accept",
            )
        except MissingRequiredClaimError as err:
            claim_name = getattr(err, "claim", "")
            if not claim_name:
                match = re.search(r"claim\s*[:\s]\s*(\w+)", str(err), re.IGNORECASE)
                if match:
                    claim_name = match.group(1).lower()

            if claim_name == "email":
                return VerifyAgentTokenResult(
                    ok=False,
                    code="MISSING_EMAIL",
                    error="Token carries no usable email claim",
                )
            if claim_name == "aud":
                return VerifyAgentTokenResult(
                    ok=False,
                    code="AUDIENCE_MISMATCH",
                    error="Audience mismatch: token was minted for different domain",
                )
            if claim_name == "iss":
                return VerifyAgentTokenResult(
                    ok=False,
                    code="ISSUER_MISMATCH",
                    error="Issuer mismatch",
                )
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error=f"Missing required claim: {claim_name or err}",
            )
        except DecodeError as err:
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error=str(err),
            )
        except PyJWTError as err:
            return VerifyAgentTokenResult(
                ok=False,
                code="MALFORMED_TOKEN",
                error=str(err),
            )

        email = payload.get("email")
        if not isinstance(email, str) or not email:
            return VerifyAgentTokenResult(
                ok=False,
                code="MISSING_EMAIL",
                error="Token carries no usable email claim",
            )

        sub = payload.get("sub")
        sub_str = str(sub) if sub is not None else email
        exp = payload.get("exp")
        exp_int = int(exp) if isinstance(exp, (int, float)) else 0
        jti = payload.get("jti")
        jti_str = str(jti) if jti is not None else ""

        return VerifyAgentTokenResult(
            ok=True,
            email=email,
            sub=sub_str,
            user_id=sub_str,
            expires_at=exp_int,
            jti=jti_str,
            audience=normalized_aud,
        )


_DEFAULT_VERIFIER = Verifier()


def verify_agent_token(
    token: str,
    *,
    audience: str,
    issuer: str | None = None,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
    clock_tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
) -> VerifyAgentTokenResult:
    """Verifies an AgentOnboard ephemeral session token synchronously."""
    return _DEFAULT_VERIFIER.verify(
        token,
        audience=audience,
        issuer=issuer,
        jwks_url=jwks_url,
        jwks=jwks,
        fetch_jwks=fetch_jwks,
        clock_tolerance_seconds=clock_tolerance_seconds,
    )


async def verify_agent_token_async(
    token: str,
    *,
    audience: str,
    issuer: str | None = None,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
    fetch_jwks_async: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
    clock_tolerance_seconds: int = DEFAULT_CLOCK_TOLERANCE_SECONDS,
) -> VerifyAgentTokenResult:
    """Verifies an AgentOnboard ephemeral session token asynchronously."""
    return await _DEFAULT_VERIFIER.verify_async(
        token,
        audience=audience,
        issuer=issuer,
        jwks_url=jwks_url,
        jwks=jwks,
        fetch_jwks=fetch_jwks,
        fetch_jwks_async=fetch_jwks_async,
        clock_tolerance_seconds=clock_tolerance_seconds,
    )
