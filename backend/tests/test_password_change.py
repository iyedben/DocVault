"""Tests for self-service authenticated password change endpoint."""

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
from app.security.passwords import hash_password, verify_password
from app.security.sessions import issue_auth_session
from app.security.tokens import hash_token
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

INITIAL_PASSWORD = "Initial-Password!2026"
NEW_PASSWORD = "Updated-SecurePassword#99"


@pytest.fixture
def pwd_client() -> Generator[tuple[httpx.AsyncClient, sessionmaker[Session], User, str, str, str], None, None]:
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

        user = User(
            username="pwdtester",
            password_hash=hash_password(INITIAL_PASSWORD),
            role=role,
        )
        db.add(user)
        db.flush()

        settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)
        # Primary session (current)
        _, session_token, csrf_token = issue_auth_session(db, user, settings)
        # Secondary session (other device/tab)
        _, other_session_token, _ = issue_auth_session(db, user, settings)
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
            yield client, session_factory, user, session_token, csrf_token, other_session_token

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


def test_password_change_unauthenticated(pwd_client) -> None:
    client, _, _, _, _, _ = pwd_client
    response = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            headers={"X-CSRF-Token": "some-token"},
        )
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_password_change_missing_or_invalid_csrf(pwd_client) -> None:
    client, _, _, session_token, _, _ = pwd_client
    client.cookies.set("docvault_session", session_token)

    # Missing CSRF header
    r1 = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
        )
    )
    assert r1.status_code == 403
    assert r1.json()["detail"] == "CSRF validation failed"

    # Invalid CSRF header
    r2 = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            headers={"X-CSRF-Token": "wrong-csrf-token"},
        )
    )
    assert r2.status_code == 403
    assert r2.json()["detail"] == "CSRF validation failed"


def test_password_change_get_method_rejected(pwd_client) -> None:
    client, _, _, session_token, csrf_token, _ = pwd_client
    client.cookies.set("docvault_session", session_token)
    response = asyncio.run(
        client.get(
            "/api/v1/auth/password",
            headers={"X-CSRF-Token": csrf_token},
        )
    )
    assert response.status_code == 405


def test_password_change_wrong_current_password(pwd_client) -> None:
    client, _, _, session_token, csrf_token, _ = pwd_client
    client.cookies.set("docvault_session", session_token)

    response = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": "IncorrectPassword!2026", "new_password": NEW_PASSWORD},
            headers={"X-CSRF-Token": csrf_token},
        )
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid current password"


def test_password_change_invalid_new_password_policy(pwd_client) -> None:
    client, _, _, session_token, csrf_token, _ = pwd_client
    client.cookies.set("docvault_session", session_token)

    # Too short (< 12)
    r1 = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": "Short!1"},
            headers={"X-CSRF-Token": csrf_token},
        )
    )
    assert r1.status_code == 422

    # Lacks character categories (only lowercase and digits, lacks upper or symbol)
    r2 = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": "alllowercaseanddigits12345"},
            headers={"X-CSRF-Token": csrf_token},
        )
    )
    assert r2.status_code == 422


def test_password_change_same_as_current(pwd_client) -> None:
    client, _, _, session_token, csrf_token, _ = pwd_client
    client.cookies.set("docvault_session", session_token)

    response = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": INITIAL_PASSWORD},
            headers={"X-CSRF-Token": csrf_token},
        )
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "New password must be different from current password"


def test_password_change_successful(pwd_client) -> None:
    client, session_factory, user, session_token, csrf_token, other_session_token = pwd_client
    client.cookies.set("docvault_session", session_token)

    response = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            headers={"X-CSRF-Token": csrf_token},
        )
    )
    assert response.status_code == 200
    data = response.json()
    assert data["detail"] == "Password changed successfully"
    new_csrf_token = data["csrf_token"]
    assert new_csrf_token != csrf_token
    assert "no-store" in response.headers["cache-control"]

    with session_factory() as db:
        # Check new password hash
        u = db.scalar(select(User).where(User.id == user.id))
        assert u is not None
        assert verify_password(NEW_PASSWORD, u.password_hash)
        assert not verify_password(INITIAL_PASSWORD, u.password_hash)

        # Check other session was revoked
        other_sess = db.scalar(select(AuthSession).where(AuthSession.session_token_hash == hash_token(other_session_token)))
        assert other_sess is not None
        assert other_sess.revoked_at is not None

        # Check current session remains active
        current_sess = db.scalar(select(AuthSession).where(AuthSession.session_token_hash == hash_token(session_token)))
        assert current_sess is not None
        assert current_sess.revoked_at is None

    # Verify that the other session is rejected when attempting requests
    client.cookies.set("docvault_session", other_session_token)
    r_other = asyncio.run(client.get("/api/v1/auth/me"))
    assert r_other.status_code == 401

    # Verify that current session is still valid and can make requests
    client.cookies.set("docvault_session", session_token)
    r_me = asyncio.run(client.get("/api/v1/auth/me"))
    assert r_me.status_code == 200
    assert r_me.json()["username"] == "pwdtester"

    # Verify that current session can use the new CSRF token for mutating action (logout)
    r_logout = asyncio.run(
        client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": new_csrf_token},
        )
    )
    assert r_logout.status_code == 204
