"""Tests for authenticated CSRF token recovery and rotation via POST bootstrap."""

from __future__ import annotations

import asyncio
from collections.abc import Generator

import httpx
import pytest
from app.api.dependencies import get_db
from app.core.config import AuthSettings
from app.db.base import Base
from app.main import app
from app.models import AuthSession, Role, User
from app.models.user import utcnow
from app.security.sessions import issue_auth_session
from app.security.tokens import hash_token
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def auth_client() -> Generator[tuple[httpx.AsyncClient, sessionmaker[Session], User, str, str], None, None]:
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
        admin_role = Role(name="administrator")
        db.add(admin_role)
        db.flush()

        user = User(username="csrftester", password_hash="hash-1234567890", role=role)
        db.add(user)
        db.flush()

        settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)
        _auth_session, session_token, csrf_token = issue_auth_session(db, user, settings)
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
            yield client, session_factory, user, session_token, csrf_token

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


def test_csrf_recovery_unauthenticated(auth_client) -> None:
    client, _, _, _, _ = auth_client
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"}))
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_csrf_recovery_invalid_cookie(auth_client) -> None:
    client, _, _, _, _ = auth_client
    client.cookies.set("docvault_session", "completely-invalid-opaque-token")
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"}))
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_csrf_recovery_revoked_session(auth_client) -> None:
    client, session_factory, user, session_token, _ = auth_client
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == user.id))
        assert sess is not None
        sess.revoked_at = utcnow()
        db.commit()

    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"}))
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_csrf_recovery_inactive_user(auth_client) -> None:
    client, session_factory, user, session_token, _ = auth_client
    with session_factory() as db:
        u = db.scalar(select(User).where(User.id == user.id))
        assert u is not None
        u.is_active = False
        db.commit()

    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"}))
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_csrf_recovery_get_method_not_allowed(auth_client) -> None:
    client, _, _, session_token, _ = auth_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(client.get("/api/v1/auth/csrf"))
    assert response.status_code == 405


def test_csrf_recovery_untrusted_origin(auth_client) -> None:
    client, _, _, session_token, _ = auth_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "https://evil.attacker.com"}))
    assert response.status_code == 403
    assert response.json()["detail"] == "Request origin is not authorized"


def test_csrf_recovery_untrusted_referer(auth_client) -> None:
    client, _, _, session_token, _ = auth_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Referer": "https://evil.attacker.com/page"}))
    assert response.status_code == 403
    assert response.json()["detail"] == "Request referer is not authorized"


def test_csrf_recovery_cross_site_fetch_site(auth_client) -> None:
    client, _, _, session_token, _ = auth_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(
        client.post(
            "/api/v1/auth/csrf",
            headers={"Origin": "http://testserver", "Sec-Fetch-Site": "cross-site"},
        )
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-site bootstrap request rejected"


def test_csrf_recovery_navigate_fetch_mode(auth_client) -> None:
    client, _, _, session_token, _ = auth_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(
        client.post(
            "/api/v1/auth/csrf",
            headers={"Origin": "http://testserver", "Sec-Fetch-Mode": "navigate"},
        )
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Navigation requests are not permitted"


def test_csrf_recovery_nested_navigate_fetch_mode(auth_client) -> None:
    client, _, _, session_token, _ = auth_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(
        client.post(
            "/api/v1/auth/csrf",
            headers={"Origin": "http://testserver", "Sec-Fetch-Mode": "nested-navigate"},
        )
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Navigation requests are not permitted"


def test_csrf_recovery_missing_origin_and_fetch_metadata(auth_client) -> None:
    client, _, _, session_token, _ = auth_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(client.post("/api/v1/auth/csrf"))
    assert response.status_code == 403
    assert response.json()["detail"] == "Origin or fetch metadata header required"


def test_csrf_recovery_same_origin_fetch_site_without_origin(auth_client) -> None:
    client, _, _, session_token, _ = auth_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Sec-Fetch-Site": "same-origin"}))
    assert response.status_code == 200
    assert "csrf_token" in response.json()


def test_csrf_recovery_successful_rotation_and_usage(auth_client) -> None:
    client, session_factory, user, session_token, original_csrf = auth_client
    client.cookies.set("docvault_session", session_token)

    # 1. Retrieve a new CSRF token via POST with trusted origin
    response = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"}))
    assert response.status_code == 200
    assert "private, no-store" in response.headers["cache-control"]
    data = response.json()
    new_csrf = data["csrf_token"]
    assert new_csrf != original_csrf
    assert len(new_csrf) >= 32

    # 2. Verify hash in DB is updated
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == user.id))
        assert sess is not None
        assert sess.csrf_token_hash == hash_token(new_csrf)
        assert sess.csrf_token_hash != hash_token(original_csrf)

    # 3. Old CSRF token is now rejected on a mutating request
    mutating_old = asyncio.run(
        client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": original_csrf},
        )
    )
    assert mutating_old.status_code == 403
    assert mutating_old.json()["detail"] == "CSRF validation failed"

    # 4. New CSRF token is accepted on a mutating request
    mutating_new = asyncio.run(
        client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": new_csrf},
        )
    )
    assert mutating_new.status_code == 204


def test_csrf_recovery_consecutive_rotations(auth_client) -> None:
    client, session_factory, user, session_token, initial_csrf = auth_client
    client.cookies.set("docvault_session", session_token)

    resp1 = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"}))
    token1 = resp1.json()["csrf_token"]
    assert token1 != initial_csrf

    resp2 = asyncio.run(client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"}))
    token2 = resp2.json()["csrf_token"]
    assert token2 != token1

    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == user.id))
        assert sess is not None
        assert sess.csrf_token_hash == hash_token(token2)
