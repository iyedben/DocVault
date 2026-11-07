"""Tests for authenticated user lookup endpoint."""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from uuid import UUID

import httpx
import pytest
from app.api.dependencies import get_db
from app.core.config import AuthSettings
from app.db.base import Base
from app.main import app
from app.models import Role, User
from app.security.sessions import issue_auth_session
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def lookup_harness() -> Generator[tuple[httpx.AsyncClient, sessionmaker[Session], str, str, str], None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with session_factory() as db:
        user_role = Role(name="user")
        admin_role = Role(name="administrator")
        db.add_all([user_role, admin_role])
        db.flush()

        # Create active regular user
        alice = User(username="alice_regular", password_hash="hash-alice", role=user_role)
        # Create active administrator
        charlie_admin = User(username="charlie_admin", password_hash="hash-charlie", role=admin_role)
        # Create inactive user
        deactivated = User(username="bob_inactive", password_hash="hash-bob", role=user_role, is_active=False)
        # Create active target users for partial match
        target1 = User(username="bob_active1", password_hash="hash-b1", role=user_role)
        target2 = User(username="bob_active2", password_hash="hash-b2", role=user_role)
        target3 = User(username="superbob", password_hash="hash-sb", role=user_role)

        # Create 12 users matching "bulk_target" to test result limiting
        bulk_users = [
            User(username=f"bulk_target_{i:02d}", password_hash="hash-bulk", role=user_role)
            for i in range(12)
        ]

        db.add_all([alice, charlie_admin, deactivated, target1, target2, target3, *bulk_users])
        db.flush()

        settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)
        _, alice_session, _ = issue_auth_session(db, alice, settings)
        _, admin_session, _ = issue_auth_session(db, charlie_admin, settings)
        _, deact_session, _ = issue_auth_session(db, deactivated, settings)
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
            yield client, session_factory, alice_session, admin_session, deact_session

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


def test_user_lookup_unauthenticated(lookup_harness) -> None:
    client, _, _, _, _ = lookup_harness
    response = asyncio.run(client.get("/api/v1/users/lookup?username=bob"))
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_user_lookup_inactive_caller(lookup_harness) -> None:
    client, _, _, _, deact_session = lookup_harness
    client.cookies.set("docvault_session", deact_session)
    response = asyncio.run(client.get("/api/v1/users/lookup?username=bob"))
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_user_lookup_query_too_short(lookup_harness) -> None:
    client, _, alice_session, _, _ = lookup_harness
    client.cookies.set("docvault_session", alice_session)

    # Missing query param
    r1 = asyncio.run(client.get("/api/v1/users/lookup"))
    assert r1.status_code == 422

    # Query with 1 character
    r2 = asyncio.run(client.get("/api/v1/users/lookup?username=b"))
    assert r2.status_code == 422

    # Query with spaces only
    r3 = asyncio.run(client.get("/api/v1/users/lookup?username=%20%20%20"))
    assert r3.status_code == 422


def test_user_lookup_as_regular_user_and_schema_safety(lookup_harness) -> None:
    client, _, alice_session, _, _ = lookup_harness
    client.cookies.set("docvault_session", alice_session)

    response = asyncio.run(client.get("/api/v1/users/lookup?username=bob"))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 3

    usernames = [u["username"] for u in data]
    assert "bob_active1" in usernames
    assert "bob_active2" in usernames
    assert "superbob" in usernames
    assert "bob_inactive" not in usernames  # Inactive user must be excluded!

    # Verify schema fields: ONLY id and username
    for item in data:
        assert set(item.keys()) == {"id", "username"}
        # Must be valid UUID
        UUID(item["id"])
        assert "password_hash" not in item
        assert "role" not in item
        assert "is_active" not in item


def test_user_lookup_as_admin_user(lookup_harness) -> None:
    client, _, _, admin_session, _ = lookup_harness
    client.cookies.set("docvault_session", admin_session)

    response = asyncio.run(client.get("/api/v1/users/lookup?username=alice"))
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["username"] == "alice_regular"


def test_user_lookup_case_insensitive(lookup_harness) -> None:
    client, _, alice_session, _, _ = lookup_harness
    client.cookies.set("docvault_session", alice_session)

    response = asyncio.run(client.get("/api/v1/users/lookup?username=BOB"))
    assert response.status_code == 200
    data = response.json()
    usernames = [u["username"] for u in data]
    assert "bob_active1" in usernames
    assert "bob_active2" in usernames
    assert "superbob" in usernames


def test_user_lookup_result_limit(lookup_harness) -> None:
    client, _, alice_session, _, _ = lookup_harness
    client.cookies.set("docvault_session", alice_session)

    response = asyncio.run(client.get("/api/v1/users/lookup?username=bulk_target"))
    assert response.status_code == 200
    data = response.json()
    # 12 exist in DB, but max limit of 10 should be returned
    assert len(data) == 10
    for u in data:
        assert u["username"].startswith("bulk_target_")


def test_user_lookup_no_matches(lookup_harness) -> None:
    client, _, alice_session, _, _ = lookup_harness
    client.cookies.set("docvault_session", alice_session)

    response = asyncio.run(client.get("/api/v1/users/lookup?username=nonexistent_query"))
    assert response.status_code == 200
    assert response.json() == []
