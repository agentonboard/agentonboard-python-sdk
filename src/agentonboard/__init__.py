"""
AgentOnboard Python SDK — Universal identity layer for AI agents.
"""

from agentonboard.account import (
    AccountCreator,
    AccountOutcome,
    AccountResolver,
    AgentIdentity,
    AsyncAccountCreator,
    AsyncAccountResolver,
    create_agent_account,
    create_agent_account_async,
    normalize_email,
    verify_agent_account,
    verify_agent_account_async,
)
from agentonboard.codes import (
    ACCOUNT_ERROR_DESCRIPTIONS,
    VERIFY_ERROR_DESCRIPTIONS,
    AccountErrorCode,
    VerifyErrorCode,
    status_from_code,
)
from agentonboard.verify import (
    DEFAULT_CLOCK_TOLERANCE_SECONDS,
    Verifier,
    VerifyAgentTokenResult,
    normalize_audience,
    verify_agent_token,
    verify_agent_token_async,
)

__version__ = "0.1.0"

__all__ = [
    "ACCOUNT_ERROR_DESCRIPTIONS",
    "AccountCreator",
    "AccountErrorCode",
    "AccountOutcome",
    "AccountResolver",
    "AgentIdentity",
    "AsyncAccountCreator",
    "AsyncAccountResolver",
    "DEFAULT_CLOCK_TOLERANCE_SECONDS",
    "VERIFY_ERROR_DESCRIPTIONS",
    "Verifier",
    "VerifyAgentTokenResult",
    "VerifyErrorCode",
    "__version__",
    "create_agent_account",
    "create_agent_account_async",
    "normalize_audience",
    "normalize_email",
    "status_from_code",
    "verify_agent_account",
    "verify_agent_account_async",
    "verify_agent_token",
    "verify_agent_token_async",
]
