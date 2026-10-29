import pytest

from agentonboard.account import (
    AgentIdentity,
    create_agent_account,
    create_agent_account_async,
    normalize_email,
    verify_agent_account,
    verify_agent_account_async,
)
from agentonboard.codes import status_from_code


def test_normalize_email():
    assert normalize_email("  Test@Example.COM  ") == "test@example.com"
    assert normalize_email("") == ""
    assert normalize_email(None) == ""


def make_callback(desc, seen):
    def cb(identity: AgentIdentity):
        seen.append(identity)
        how = desc["returns"]
        if how == "throw":
            raise RuntimeError(desc.get("message", "Test error"))
        if how == "user":
            return desc["value"]
        return None

    return cb


def make_async_callback(desc, seen):
    async def cb(identity: AgentIdentity):
        seen.append(identity)
        how = desc["returns"]
        if how == "throw":
            raise RuntimeError(desc.get("message", "Test error"))
        if how == "user":
            return desc["value"]
        return None

    return cb


def test_sync_account_vectors(fixture_data):
    v_map = {c["name"]: c for c in fixture_data["verification"]}

    for case in fixture_data["account"]:
        cname = case["name"]
        v_case = v_map[case["token"]]
        token = v_case["token"]
        audience = v_case["audience"]
        issuer = v_case["issuer"]
        jwks = fixture_data["keys"][v_case["keySet"]]["jwks"]

        resolver_seen = []
        resolver = make_callback(case["resolver"], resolver_seen)

        outcome = verify_agent_account(
            token=token,
            audience=audience,
            issuer=issuer,
            jwks=jwks,
            resolver=resolver,
        )

        exp = case["expect"]
        assert len(resolver_seen) == exp["resolverCalls"], f"[{cname}] resolverCalls mismatch"
        if exp.get("resolverIdentity"):
            assert (
                resolver_seen[0].email == exp["resolverIdentity"]["email"]
            ), f"[{cname}] resolverIdentity mismatch"
        if exp["ok"]:
            assert outcome.ok is True, f"[{cname}] Expected ok=True"
            assert outcome.user == exp["user"], f"[{cname}] user mismatch"
            assert outcome.email == exp["email"], f"[{cname}] email mismatch"
        else:
            assert outcome.ok is False, f"[{cname}] Expected ok=False"
            assert outcome.code == exp["code"], f"[{cname}] code mismatch"
            assert status_from_code(outcome.code) == exp["status"], f"[{cname}] status mismatch"


def test_sync_account_create_vectors(fixture_data):
    v_map = {c["name"]: c for c in fixture_data["verification"]}

    for case in fixture_data["accountCreate"]:
        cname = case["name"]
        v_case = v_map[case["token"]]
        token = v_case["token"]
        audience = v_case["audience"]
        issuer = v_case["issuer"]
        jwks = fixture_data["keys"][v_case["keySet"]]["jwks"]

        resolver_seen = []
        resolver = make_callback(case["resolver"], resolver_seen)
        creator_seen = []
        creator = make_callback(case["creator"], creator_seen)

        outcome = create_agent_account(
            token=token,
            audience=audience,
            issuer=issuer,
            jwks=jwks,
            resolver=resolver,
            creator=creator,
        )

        exp = case["expect"]
        assert len(resolver_seen) == exp["resolverCalls"], f"[{cname}] resolverCalls mismatch"
        assert len(creator_seen) == exp["createCalls"], f"[{cname}] createCalls mismatch"
        if exp.get("resolverIdentity"):
            assert (
                resolver_seen[0].email == exp["resolverIdentity"]["email"]
            ), f"[{cname}] resolverIdentity mismatch"
        if exp.get("createIdentity"):
            assert (
                creator_seen[0].email == exp["createIdentity"]["email"]
            ), f"[{cname}] createIdentity mismatch"
        if exp["ok"]:
            assert outcome.ok is True, f"[{cname}] Expected ok=True"
            assert outcome.user == exp["user"], f"[{cname}] user mismatch"
            assert outcome.email == exp["email"], f"[{cname}] email mismatch"
            assert outcome.created == exp["created"], f"[{cname}] created mismatch"
        else:
            assert outcome.ok is False, f"[{cname}] Expected ok=False"
            assert outcome.code == exp["code"], f"[{cname}] code mismatch"
            assert status_from_code(outcome.code) == exp["status"], f"[{cname}] status mismatch"


@pytest.mark.asyncio
async def test_async_account_vectors(fixture_data):
    v_map = {c["name"]: c for c in fixture_data["verification"]}

    for case in fixture_data["account"]:
        cname = case["name"]
        v_case = v_map[case["token"]]
        token = v_case["token"]
        audience = v_case["audience"]
        issuer = v_case["issuer"]
        jwks = fixture_data["keys"][v_case["keySet"]]["jwks"]

        resolver_seen = []
        resolver = make_async_callback(case["resolver"], resolver_seen)

        outcome = await verify_agent_account_async(
            token=token,
            audience=audience,
            issuer=issuer,
            jwks=jwks,
            resolver=resolver,
        )

        exp = case["expect"]
        assert len(resolver_seen) == exp["resolverCalls"], f"[{cname}] resolverCalls mismatch"
        if exp["ok"]:
            assert outcome.ok is True
            assert outcome.user == exp["user"]
        else:
            assert outcome.ok is False
            assert outcome.code == exp["code"]


@pytest.mark.asyncio
async def test_async_account_create_vectors(fixture_data):
    v_map = {c["name"]: c for c in fixture_data["verification"]}

    for case in fixture_data["accountCreate"]:
        cname = case["name"]
        v_case = v_map[case["token"]]
        token = v_case["token"]
        audience = v_case["audience"]
        issuer = v_case["issuer"]
        jwks = fixture_data["keys"][v_case["keySet"]]["jwks"]

        resolver_seen = []
        resolver = make_async_callback(case["resolver"], resolver_seen)
        creator_seen = []
        creator = make_async_callback(case["creator"], creator_seen)

        outcome = await create_agent_account_async(
            token=token,
            audience=audience,
            issuer=issuer,
            jwks=jwks,
            resolver=resolver,
            creator=creator,
        )

        exp = case["expect"]
        assert len(resolver_seen) == exp["resolverCalls"], f"[{cname}] resolverCalls mismatch"
        assert len(creator_seen) == exp["createCalls"], f"[{cname}] createCalls mismatch"
        if exp["ok"]:
            assert outcome.ok is True, f"[{cname}] Expected ok=True"
            assert outcome.user == exp["user"], f"[{cname}] user mismatch"
            assert outcome.created == exp["created"], f"[{cname}] created mismatch"
        else:
            assert outcome.ok is False, f"[{cname}] Expected ok=False"
            assert outcome.code == exp["code"], f"[{cname}] code mismatch"
