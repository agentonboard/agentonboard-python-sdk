"""
Every failure verify_agent_token and verify_agent_account can report.

Published vocabulary: codes are only ever added, never renamed or removed, because partners
branch on them. Keep this list short — every code is a decision each language SDK has
to make identically (plans/0008-sdk-design.md §6).
"""

from typing import Literal

VerifyErrorCode = Literal[
    "EXPIRED",
    "INVALID_SIGNATURE",
    "AUDIENCE_MISMATCH",
    "ISSUER_MISMATCH",
    "MALFORMED_TOKEN",
    "CONFIG_ERROR",
    "UNKNOWN_KEY",
    "KEY_SOURCE_UNAVAILABLE",
    "MISSING_EMAIL",
]

AccountErrorCode = Literal[
    VerifyErrorCode,
    "ACCOUNT_REQUIRED",
    "RESOLVER_ERROR",
]

VERIFY_ERROR_DESCRIPTIONS: dict[VerifyErrorCode, str] = {
    "EXPIRED": "The token's exp claim is in the past, beyond the clock-skew tolerance.",
    "INVALID_SIGNATURE": (
        "The signature did not verify against a published key, or the token used an "
        "algorithm this SDK does not accept."
    ),
    "AUDIENCE_MISMATCH": "The token was minted for a different audience, or carries no aud claim.",
    "ISSUER_MISMATCH": "The token was minted by a different issuer, or carries no iss claim.",
    "MALFORMED_TOKEN": (
        "The token is not a readable JWT, or a claim this SDK requires is absent or unusable."
    ),
    "CONFIG_ERROR": "The call itself is wrong: audience, issuer, JWKS URL, or clock-skew tolerance.",
    "UNKNOWN_KEY": (
        "The token's kid matched no key in the key set this SDK could obtain. The code does "
        "not say why: the key may be revoked or rotated away, the token may be forged, or "
        "the key endpoint may be unreachable and leave this SDK holding an out-of-date set."
    ),
    "KEY_SOURCE_UNAVAILABLE": (
        "This SDK could not obtain a signing key: the key set could not be fetched, the "
        "published set is not one this SDK can verify against, or it publishes more than one "
        "key for the token's kid."
    ),
    "MISSING_EMAIL": "The token verified but carries no usable email claim to identify the human.",
}

ACCOUNT_ERROR_DESCRIPTIONS: dict[AccountErrorCode, str] = {
    **VERIFY_ERROR_DESCRIPTIONS,  # type: ignore[dict-item]
    "ACCOUNT_REQUIRED": (
        "The token verified, but the partner resolver returned no account for this identity."
    ),
    "RESOLVER_ERROR": "The partner's account lookup or creation callback threw an error.",
}


def status_from_code(code: str | None) -> int:
    """
    Turns a verification or account failure code into an HTTP status code.
    Rules per agent-token-v1 statusMapping:
    - 403 for ACCOUNT_REQUIRED
    - 500 for RESOLVER_ERROR and CONFIG_ERROR
    - 401 for all other error codes
    """
    if code == "ACCOUNT_REQUIRED":
        return 403
    if code in ("RESOLVER_ERROR", "CONFIG_ERROR"):
        return 500
    return 401

