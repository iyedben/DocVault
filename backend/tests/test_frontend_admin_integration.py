"""Tests for Phase B6 role-gated administration console integration.
Verifies administrative access controls, user listing, user provisioning,
account activation/deactivation, role modifications, CSRF enforcement,
and static asset delivery with strict Content Security Policy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from uuid import uuid4

import httpx
import pytest
from app.api.dependencies import get_db
from app.core.config import AuthSettings
from app.db.base import Base
from app.main import app
from app.models import AuthSession, Role, User
from app.security.passwords import hash_password, verify_password
from app.security.sessions import issue_auth_session
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

INITIAL_PASSWORD = "AliceUserPassword#2026"
ADMIN_PASSWORD = "PrimaryAdminPassword#2026"
ADMIN2_PASSWORD = "SecondaryAdminPassword#2026"
NEW_USER_PASSWORD = "BrandNewUserPassword#99"


@pytest.fixture
def admin_env() -> Generator[
    tuple[
        httpx.AsyncClient,
        sessionmaker[Session],
        User,  # alice (regular user)
        User,  # admin1 (primary admin)
        User,  # admin2 (secondary admin)
        str,   # alice session token
        str,   # alice csrf token
        str,   # admin1 session token
        str,   # admin1 csrf token
        str,   # admin2 session token
        str,   # admin2 csrf token
    ],
    None,
    None,
]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)

    with session_factory() as db:
        user_role = Role(name="user")
        admin_role = Role(name="administrator")
        db.add_all([user_role, admin_role])
        db.flush()

        alice = User(
            username="alice",
            password_hash=hash_password(INITIAL_PASSWORD),
            role=user_role,
        )
        admin1 = User(
            username="admin1",
            password_hash=hash_password(ADMIN_PASSWORD),
            role=admin_role,
        )
        admin2 = User(
            username="admin2",
            password_hash=hash_password(ADMIN2_PASSWORD),
            role=admin_role,
        )
        db.add_all([alice, admin1, admin2])
        db.flush()

        _, alice_session, alice_csrf = issue_auth_session(db, alice, settings)
        _, admin1_session, admin1_csrf = issue_auth_session(db, admin1, settings)
        _, admin2_session, admin2_csrf = issue_auth_session(db, admin2, settings)
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
            yield (
                client,
                session_factory,
                alice,
                admin1,
                admin2,
                alice_session,
                alice_csrf,
                admin1_session,
                admin1_csrf,
                admin2_session,
                admin2_csrf,
            )

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


def test_anonymous_access_to_admin_endpoints_denied(admin_env) -> None:
    """1. Anonymous requests to all administrator endpoints are strictly rejected with 401."""
    client, _, _, admin1, _, _, _, _, _, _, _ = admin_env

    # GET roster
    res_get = asyncio.run(client.get("/api/v1/admin/users"))
    assert res_get.status_code == 401
    assert res_get.json()["detail"] == "Authentication required"

    # POST create user
    res_post = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "newguy", "password": NEW_USER_PASSWORD, "role": "user"},
            headers={"X-CSRF-Token": "invalid-csrf"},
        )
    )
    assert res_post.status_code == 401

    # PATCH status
    res_status = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{admin1.id}/status",
            json={"is_active": False},
            headers={"X-CSRF-Token": "invalid-csrf"},
        )
    )
    assert res_status.status_code == 401

    # PATCH role
    res_role = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{admin1.id}/role",
            json={"role": "user"},
            headers={"X-CSRF-Token": "invalid-csrf"},
        )
    )
    assert res_role.status_code == 401


def test_ordinary_user_access_to_admin_endpoints_denied(admin_env) -> None:
    """2. Ordinary users (role='user') are strictly forbidden (403) from accessing admin endpoints."""
    client, _, _, admin1, _, alice_session, alice_csrf, _, _, _, _ = admin_env
    user_headers = {
        "Cookie": f"docvault_session={alice_session}",
        "X-CSRF-Token": alice_csrf,
    }

    # GET roster
    res_get = asyncio.run(
        client.get("/api/v1/admin/users", headers={"Cookie": f"docvault_session={alice_session}"})
    )
    assert res_get.status_code == 403
    assert res_get.json()["detail"] == "Administrator access required"

    # POST create user
    res_post = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "illegaluser", "password": NEW_USER_PASSWORD, "role": "user"},
            headers=user_headers,
        )
    )
    assert res_post.status_code == 403
    assert res_post.json()["detail"] == "Administrator access required"

    # PATCH status
    res_status = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{admin1.id}/status",
            json={"is_active": False},
            headers=user_headers,
        )
    )
    assert res_status.status_code == 403

    # PATCH role
    res_role = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{admin1.id}/role",
            json={"role": "administrator"},
            headers=user_headers,
        )
    )
    assert res_role.status_code == 403


def test_admin_user_listing_success(admin_env) -> None:
    """3. Administrators can list all user accounts without exposing hashes or sessions."""
    client, _, _, _, _, _, _, admin1_session, _, _, _ = admin_env

    res = asyncio.run(
        client.get("/api/v1/admin/users", headers={"Cookie": f"docvault_session={admin1_session}"})
    )
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 3

    usernames = {u["username"] for u in data}
    assert usernames == {"admin1", "admin2", "alice"}

    for user in data:
        assert "id" in user
        assert "username" in user
        assert "role" in user
        assert "is_active" in user
        assert "created_at" in user
        assert "updated_at" in user
        # Security invariant: sensitive fields are never leaked
        assert "password_hash" not in user
        assert "sessions" not in user
        assert "password" not in user


def test_admin_user_provisioning_success(admin_env) -> None:
    """4. Administrators can provision new users and assigned roles with valid passwords."""
    client, session_factory, _, _, _, _, _, admin1_session, admin1_csrf, _, _ = admin_env
    admin_headers = {
        "Cookie": f"docvault_session={admin1_session}",
        "X-CSRF-Token": admin1_csrf,
    }

    # Provision standard user
    res_user = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "bob.smith", "password": NEW_USER_PASSWORD, "role": "user"},
            headers=admin_headers,
        )
    )
    assert res_user.status_code == 201
    bob_data = res_user.json()
    assert bob_data["username"] == "bob.smith"
    assert bob_data["role"] == "user"
    assert bob_data["is_active"] is True

    # Provision administrator
    res_admin = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "carol_admin", "password": NEW_USER_PASSWORD, "role": "administrator"},
            headers=admin_headers,
        )
    )
    assert res_admin.status_code == 201
    carol_data = res_admin.json()
    assert carol_data["username"] == "carol_admin"
    assert carol_data["role"] == "administrator"

    # Verify newly created user can log in
    res_login = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "bob.smith", "password": NEW_USER_PASSWORD},
        )
    )
    assert res_login.status_code == 200
    assert res_login.json()["user"]["username"] == "bob.smith"

    # Verify password hash in database
    with session_factory() as db:
        bob_db = db.scalar(select(User).where(User.username == "bob.smith"))
        assert bob_db is not None
        assert verify_password(NEW_USER_PASSWORD, bob_db.password_hash)


def test_admin_user_provisioning_validation_and_conflict(admin_env) -> None:
    """5. User provisioning enforces duplicate prevention, username format, and password policy."""
    client, _, _, _, _, _, _, admin1_session, admin1_csrf, _, _ = admin_env
    admin_headers = {
        "Cookie": f"docvault_session={admin1_session}",
        "X-CSRF-Token": admin1_csrf,
    }

    # Duplicate username returns 409 Conflict
    res_dup = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "alice", "password": NEW_USER_PASSWORD, "role": "user"},
            headers=admin_headers,
        )
    )
    assert res_dup.status_code == 409
    assert res_dup.json()["detail"] == "Username already exists"

    # Invalid username format (too short) returns 422
    res_short_user = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "ab", "password": NEW_USER_PASSWORD, "role": "user"},
            headers=admin_headers,
        )
    )
    assert res_short_user.status_code == 422

    # Weak password (< 12 characters) returns 422
    res_short_pass = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "validname", "password": "Short#1", "role": "user"},
            headers=admin_headers,
        )
    )
    assert res_short_pass.status_code == 422

    # Weak password (< 3 character categories) returns 422
    res_simple_pass = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "validname", "password": "alllowercasecharactersonly", "role": "user"},
            headers=admin_headers,
        )
    )
    assert res_simple_pass.status_code == 422

    # CSRF failure on mutating provisioning request returns 403
    res_csrf_fail = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            json={"username": "validuser2", "password": NEW_USER_PASSWORD, "role": "user"},
            headers={"Cookie": f"docvault_session={admin1_session}", "X-CSRF-Token": "wrong-csrf"},
        )
    )
    assert res_csrf_fail.status_code == 403


def test_user_activation_and_deactivation(admin_env) -> None:
    """6. Admins can deactivate/reactivate users, revoking active sessions on deactivation."""
    client, session_factory, alice, _, _, _, _, admin1_session, admin1_csrf, _, _ = admin_env
    admin_headers = {
        "Cookie": f"docvault_session={admin1_session}",
        "X-CSRF-Token": admin1_csrf,
    }

    # Deactivate Alice
    res_deact = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{alice.id}/status",
            json={"is_active": False},
            headers=admin_headers,
        )
    )
    assert res_deact.status_code == 200
    assert res_deact.json()["is_active"] is False

    # Alice sessions should be revoked in DB
    with session_factory() as db:
        sessions = db.scalars(select(AuthSession).where(AuthSession.user_id == alice.id)).all()
        assert len(sessions) > 0
        assert all(s.revoked_at is not None for s in sessions)

    # Alice can no longer log in while deactivated
    res_login_deact = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": INITIAL_PASSWORD},
        )
    )
    assert res_login_deact.status_code == 401

    # Reactivate Alice
    res_react = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{alice.id}/status",
            json={"is_active": True},
            headers=admin_headers,
        )
    )
    assert res_react.status_code == 200
    assert res_react.json()["is_active"] is True

    # Alice can now log in again
    res_login_react = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": INITIAL_PASSWORD},
        )
    )
    assert res_login_react.status_code == 200


def test_final_active_administrator_protections(admin_env) -> None:
    """7. The system prevents deactivating or demoting the last active administrator."""
    client, _, _, admin1, admin2, _, _, admin1_session, admin1_csrf, _, _ = admin_env
    admin_headers = {
        "Cookie": f"docvault_session={admin1_session}",
        "X-CSRF-Token": admin1_csrf,
    }

    # First, deactivate admin2 so admin1 is the ONLY active administrator
    res_deact2 = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{admin2.id}/status",
            json={"is_active": False},
            headers=admin_headers,
        )
    )
    assert res_deact2.status_code == 200

    # Attempting to deactivate the final active administrator (admin1) returns 409 Conflict
    res_final_status = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{admin1.id}/status",
            json={"is_active": False},
            headers=admin_headers,
        )
    )
    assert res_final_status.status_code == 409
    assert "The final active administrator cannot be deactivated" in res_final_status.json()["detail"]

    # Attempting to demote the final active administrator (admin1) returns 409 Conflict
    res_final_role = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{admin1.id}/role",
            json={"role": "user"},
            headers=admin_headers,
        )
    )
    assert res_final_role.status_code == 409
    assert "The final active administrator cannot be demoted" in res_final_role.json()["detail"]


def test_admin_role_change_lifecycle(admin_env) -> None:
    """8. Role changes promote users to admin and demote admins when multi-admin quorum exists."""
    client, _, alice, _admin1, _, _, _, admin1_session, admin1_csrf, _, _ = admin_env
    admin_headers = {
        "Cookie": f"docvault_session={admin1_session}",
        "X-CSRF-Token": admin1_csrf,
    }

    # Promote Alice to administrator
    res_promote = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{alice.id}/role",
            json={"role": "administrator"},
            headers=admin_headers,
        )
    )
    assert res_promote.status_code == 200
    assert res_promote.json()["role"] == "administrator"

    # Demote Alice back to user
    res_demote = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{alice.id}/role",
            json={"role": "user"},
            headers=admin_headers,
        )
    )
    assert res_demote.status_code == 200
    assert res_demote.json()["role"] == "user"

    # Non-existent user ID returns 404
    missing_id = uuid4()
    res_missing = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{missing_id}/role",
            json={"role": "user"},
            headers=admin_headers,
        )
    )
    assert res_missing.status_code == 404


def test_self_deactivation_clears_cookie_when_quorum_exists(admin_env) -> None:
    """9. When multiple active admins exist, an admin deactivating self clears session cookie."""
    client, _, _, admin1, _, _, _, admin1_session, admin1_csrf, _, _ = admin_env
    admin_headers = {
        "Cookie": f"docvault_session={admin1_session}",
        "X-CSRF-Token": admin1_csrf,
    }

    # admin1 deactivates own account while admin2 is still active
    res_self_deact = asyncio.run(
        client.patch(
            f"/api/v1/admin/users/{admin1.id}/status",
            json={"is_active": False},
            headers=admin_headers,
        )
    )
    assert res_self_deact.status_code == 200
    assert res_self_deact.json()["is_active"] is False

    # Response headers must include Set-Cookie deleting docvault_session
    set_cookie_headers = res_self_deact.headers.get_list("set-cookie")
    has_cleared_cookie = any(
        "docvault_session=" in h and ('max-age=0' in h.lower() or 'expires=' in h.lower())
        for h in set_cookie_headers
    )
    assert has_cleared_cookie, f"Expected session deletion cookie in {set_cookie_headers}"


def test_admin_static_assets_and_csp(admin_env) -> None:
    """10. Frontend static assets for admin module are served with strict Content Security Policy."""
    client, _, _, _, _, _, _, _, _, _, _ = admin_env

    # 1. Admin service module is served
    res_admin_js = asyncio.run(client.get("/static/js/admin.js"))
    assert res_admin_js.status_code == 200
    assert "listAdminUsers" in res_admin_js.text
    assert "provisionAdminUser" in res_admin_js.text

    # 2. Admin view component is served
    res_view_js = asyncio.run(client.get("/static/js/views/admin.js"))
    assert res_view_js.status_code == 200
    assert "renderAdminView" in res_view_js.text

    # 3. Main SPA HTML has strict CSP without inline script/style allowances
    res_index = asyncio.run(client.get("/"))
    assert res_index.status_code == 200
    csp = res_index.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
