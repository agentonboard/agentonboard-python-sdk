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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
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


def test_django_adapter(fixture_data):
    import json

    import django
    from django.conf import settings
    from django.http import JsonResponse
    from django.test import RequestFactory

    if not settings.configured:
        settings.configure(
            DEFAULT_CHARSET="utf-8",
            SECRET_KEY="test-secret-key",
        )
        django.setup()

    from agentonboard.frameworks.django import require_agent_token as django_require_agent_token

    jwks = fixture_data["keys"]["active"]["jwks"]
    v_map = {c["name"]: c for c in fixture_data["verification"]}
    valid_token = v_map["happy_path_far_future_exp"]["token"]
    expired_token = v_map["expired_token"]["token"]

    rf = RequestFactory()

    @django_require_agent_token(
        audience="notes.com",
        issuer="https://agentonboard.test",
        jwks=jwks,
        resolver=lambda identity: (
            "user_123" if identity.email == "agent.fixture@example.com" else None
        ),
    )
    def protected_view(request, agent_user: str):
        return JsonResponse({"user": agent_user, "attr": request.agent_user})

    # 1. Missing header -> 401
    req = rf.get("/protected")
    res = protected_view(req)
    assert res.status_code == 401
    assert json.loads(res.content)["code"] == "MALFORMED_TOKEN"

    # 2. Valid token -> 200
    req = rf.get("/protected", HTTP_AUTHORIZATION=f"Bearer {valid_token}")
    res = protected_view(req)
    assert res.status_code == 200
    assert json.loads(res.content) == {"user": "user_123", "attr": "user_123"}

    # 3. Expired token -> 401 EXPIRED
    req = rf.get("/protected", HTTP_AUTHORIZATION=f"Bearer {expired_token}")
    res = protected_view(req)
    assert res.status_code == 401
    assert json.loads(res.content)["code"] == "EXPIRED"

    # 4. Unknown account -> 403 ACCOUNT_REQUIRED
    @django_require_agent_token(
        audience="notes.com",
        issuer="https://agentonboard.test",
        jwks=jwks,
        resolver=lambda _identity: None,
    )
    def unknown_user_view(request):
        return JsonResponse({"ok": True})

    req = rf.get("/protected", HTTP_AUTHORIZATION=f"Bearer {valid_token}")
    res = unknown_user_view(req)
    assert res.status_code == 403
    assert json.loads(res.content)["code"] == "ACCOUNT_REQUIRED"
