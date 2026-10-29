import json
from pathlib import Path

import pytest

from agentonboard.verify import verify_agent_token, verify_agent_token_async


@pytest.fixture
def fixture_data():
    fixture_path = Path(__file__).parent / "fixtures" / "agent-token-v1.json"
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)


def test_sync_verification_vectors(fixture_data):
    for case in fixture_data["verification"]:
        cname = case["name"]
        token = case["token"]
        audience = case["audience"]
        issuer = case["issuer"]
        key_set_name = case["keySet"]
        jwks = fixture_data["keys"][key_set_name]["jwks"]
        expected = case["expect"]

        res = verify_agent_token(
            token=token,
            audience=audience,
            issuer=issuer,
            jwks=jwks,
        )

        if expected.get("ok"):
            exp_email = expected["email"]
            assert res.ok is True, f"[{cname}] Expected ok=True, got {res}"
            assert res.email == exp_email, f"[{cname}] Email mismatch: {res.email} vs {exp_email}"
            if "sub" in expected:
                assert res.sub == expected["sub"], f"[{cname}] Sub mismatch"
            if "jti" in expected:
                assert res.jti == expected["jti"], f"[{cname}] Jti mismatch"
        else:
            exp_code = expected["code"]
            assert res.ok is False, f"[{cname}] Expected ok=False, got {res}"
            assert res.code == exp_code, (
                f"[{cname}] Code mismatch: got {res.code}, expected {exp_code}"
            )


@pytest.mark.asyncio
async def test_async_verification_vectors(fixture_data):
    for case in fixture_data["verification"]:
        cname = case["name"]
        token = case["token"]
        audience = case["audience"]
        issuer = case["issuer"]
        key_set_name = case["keySet"]
        jwks = fixture_data["keys"][key_set_name]["jwks"]
        expected = case["expect"]

        res = await verify_agent_token_async(
            token=token,
            audience=audience,
            issuer=issuer,
            jwks=jwks,
        )

        if expected.get("ok"):
            exp_email = expected["email"]
            assert res.ok is True, f"[{cname}] Expected ok=True, got {res}"
            assert res.email == exp_email, f"[{cname}] Email mismatch: {res.email} vs {exp_email}"
        else:
            exp_code = expected["code"]
            assert res.ok is False, f"[{cname}] Expected ok=False, got {res}"
            assert res.code == exp_code, (
                f"[{cname}] Code mismatch: got {res.code}, expected {exp_code}"
            )
