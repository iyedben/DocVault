"""Tests for central application-wide security and caching headers."""

from __future__ import annotations

import asyncio
from collections.abc import Generator

import httpx
import pytest
from app.api.dependencies import get_db
from app.core.config import AuthSettings
from app.db.base import Base
from app.main import app
from app.models import Role, User
from app.security.sessions import issue_auth_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def headers_client() -> Generator[tuple[httpx.AsyncClient, str], None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with session_factory() as db:
        role = Role(name="user")
        db.add(role)
        db.flush()
        user = User(username="headertester", password_hash="hash-headers", role=role)
        db.add(user)
        db.flush()
        settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)
        _, session_token, _ = issue_auth_session(db, user, settings)
        db.commit()

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client, session_token

    gen = run()
    val = asyncio.run(anext(gen))
    try:
        yield val
    finally:
        try:
            asyncio.run(anext(gen))
        except StopAsyncIteration:
            pass
        app.dependency_overrides.clear()
        engine.dispose()


def test_standard_security_headers_on_health_endpoints(headers_client) -> None:
    client, _ = headers_client
    response = asyncio.run(client.get("/health"))
    assert response.status_code == 200

    headers = response.headers
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "accelerometer=()" in headers["permissions-policy"]
    assert "camera=()" in headers["permissions-policy"]

    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "cdn.jsdelivr.net" not in csp


def test_security_headers_and_cache_control_on_api_endpoints(headers_client) -> None:
    client, session_token = headers_client
    client.cookies.set("docvault_session", session_token)

    # Test /api/v1/auth/csrf
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"}))
    assert response.status_code == 200

    headers = response.headers
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "private, no-store" in headers["cache-control"]

    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "unsafe-inline" not in csp


def test_security_headers_on_user_lookup(headers_client) -> None:
    client, session_token = headers_client
    client.cookies.set("docvault_session", session_token)

    response = asyncio.run(client.get("/api/v1/users/lookup?username=header"))
    assert response.status_code == 200

    headers = response.headers
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert "private, no-store" in headers["cache-control"]


def test_docs_csp_exception(headers_client) -> None:
    client, _ = headers_client
    response = asyncio.run(client.get("/docs"))
    assert response.status_code == 200

    csp = response.headers["content-security-policy"]
    assert "cdn.jsdelivr.net" in csp
    assert "unsafe-inline" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_no_duplicate_headers_emitted(headers_client) -> None:
    client, session_token = headers_client
    client.cookies.set("docvault_session", session_token)

    response = asyncio.run(client.get("/api/v1/documents"))
    # In ASGI / HTTP, check raw headers count for keys
    raw_keys = [k.decode("latin1").lower() for k, _ in response.headers.raw]
    for key in [
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "content-security-policy",
        "cache-control",
    ]:
        count = raw_keys.count(key)
        assert count <= 1, f"Duplicate header '{key}' found {count} times"


def test_hsts_behavior_when_secure_cookie_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")

    async def run_hsts_check():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            return await client.get("/health")

    resp = asyncio.run(run_hsts_check())
    assert resp.status_code == 200
    assert "strict-transport-security" in resp.headers
    assert resp.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"


def test_hsts_behavior_when_secure_cookie_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")

    async def run_no_hsts_check():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            return await client.get("/health")

    resp = asyncio.run(run_no_hsts_check())
    assert resp.status_code == 200
    assert "strict-transport-security" not in resp.headers
