# agentonboard-sdk (Python Partner SDK)

The Python partner SDK for [AgentOnboard](https://agentonboard.xyz) — verify ephemeral agent session tokens and safely resolve or provision partner accounts.

## Installation

```bash
pip install agentonboard-sdk
```

Optional framework shortcuts:
```bash
pip install "agentonboard-sdk[fastapi]"
pip install "agentonboard-sdk[flask]"
```

## Quickstart

### Verify an Agent Token

```python
from agentonboard import verify_agent_token

result = verify_agent_token(
    token=bearer_token,
    audience="notes.com",
)

if not result.ok:
    print(f"Auth failed: {result.code} - {result.error}")
else:
    print(f"Authenticated human: {result.email}")
```

### Async Verification

```python
from agentonboard import verify_agent_token_async

result = await verify_agent_token_async(
    token=bearer_token,
    audience="notes.com",
)
```

### Account Resolution & Provisioning

```python
from agentonboard import verify_agent_account, create_agent_account, AgentIdentity


def find_user_by_email(identity: AgentIdentity):
    return db.query(User).filter(User.email == identity.email).first()


def create_user_for_agent(identity: AgentIdentity):
    return db.create_user(email=identity.email)


# Read-only verification
outcome = verify_agent_account(
    token=bearer_token,
    audience="notes.com",
    resolver=find_user_by_email,
)

# Provisioning if account doesn't exist
outcome = create_agent_account(
    token=bearer_token,
    audience="notes.com",
    resolver=find_user_by_email,
    creator=create_user_for_agent,
)
```
