import pytest
from fastapi import Depends, FastAPI
from flask import Flask, jsonify
from httpx import ASGITransport, AsyncClient

from agentonboard.account import AgentIdentity
from agentonboard.frameworks.fastapi import AgentBearerAuth
from agentonboard.frameworks.flask import require_agent_token


@pytest.mark.asyncio
async def test_fastapi_adapter(fixture_data):
    jwks = fixture_data["keys"]["active"]["jwks"]
    v_map = {c["name"]: c for c in fixture_data["verification"]}
    valid_token = v_map["happy_path_far_future_exp"]["token"]
    expired_token = v_map["expired_token"]["token"]

    app = FastAPI()
    auth = AgentBearerAuth(
        audience="notes.com",
        issuer="https://agentonboard.test",
        jwks=jwks,
    )

    @app.get("/protected")
    async def protected_endpoint(identity: AgentIdentity = Depends(auth)):
        return {"email": identity.email}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1. Missing header
        res = await client.get("/protected")
        assert res.status_code == 401

        # 2. Valid token
        res = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res.status_code == 200
        assert res.json() == {"email": "agent.fixture@example.com"}

        # 3. Expired token
        res = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert res.status_code == 401
        assert res.json()["detail"]["code"] == "EXPIRED"


def test_flask_adapter(fixture_data):
    jwks = fixture_data["keys"]["active"]["jwks"]
    v_map = {c["name"]: c for c in fixture_data["verification"]}
    valid_token = v_map["happy_path_far_future_exp"]["token"]
    expired_token = v_map["expired_token"]["token"]

    app = Flask(__name__)

    @app.get("/protected")
    @require_agent_token(
        audience="notes.com",
        issuer="https://agentonboard.test",
        jwks=jwks,
    )
    def protected(agent_identity: AgentIdentity):
        return jsonify({"email": agent_identity.email})

    client = app.test_client()

    # 1. Missing header
    res = client.get("/protected")
    assert res.status_code == 401

    # 2. Valid token
    res = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {valid_token}"},
    )
    assert res.status_code == 200
    assert res.get_json() == {"email": "agent.fixture@example.com"}

    # 3. Expired token
    res = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res.status_code == 401
    assert res.get_json()["code"] == "EXPIRED"
