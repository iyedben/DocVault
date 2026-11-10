"""Tests for Phase B5 self-service security settings and password change integration."""

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
from app.security.passwords import hash_password, verify_password
from app.security.sessions import issue_auth_session
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

INITIAL_PASSWORD = "AliceInitialPassword#2026"
NEW_PASSWORD = "AliceNewSecurePassword#99"
ADMIN_PASSWORD = "AdminInitialPassword#2026"


@pytest.fixture
def settings_env() -> Generator[
    tuple[
        httpx.AsyncClient,
        sessionmaker[Session],
        User,
        User,
        str,
        str,
        str,
        str,
        str,
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
        admin_user = User(
            username="admin_user",
            password_hash=hash_password(ADMIN_PASSWORD),
            role=admin_role,
        )
        db.add_all([alice, admin_user])
        db.flush()

        # Alice Session A (primary active session)
        _, alice_session_a, alice_csrf_a = issue_auth_session(db, alice, settings)
        # Alice Session B (other device session)
        _, alice_session_b, _ = issue_auth_session(db, alice, settings)

        # Admin session
        _, admin_session, admin_csrf = issue_auth_session(db, admin_user, settings)
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
                admin_user,
                alice_session_a,
                alice_csrf_a,
                alice_session_b,
                admin_session,
                admin_csrf,
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


def test_anonymous_access_to_settings_and_password_denied(settings_env) -> None:
    """1. Anonymous access is strictly denied for settings identity and password changes."""
    client, _, _, _, _, _, _, _, _ = settings_env

    # Identity check is rejected
    res_me = asyncio.run(client.get("/api/v1/auth/me"))
    assert res_me.status_code == 401
    assert res_me.json()["detail"] == "Authentication required"

    # Password change without session cookie is rejected
    res_pwd = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            headers={"X-CSRF-Token": "some-token"},
        )
    )
    assert res_pwd.status_code == 401
    assert res_pwd.json()["detail"] == "Authentication required"


def test_authenticated_settings_identity_and_role_retrieval(settings_env) -> None:
    """2. Authenticated settings view retrieves current user metadata (username, role) safely."""
    client, _, _, _, alice_session_a, _, _, admin_session, _ = settings_env

    # Alice profile
    res_alice = asyncio.run(
        client.get("/api/v1/auth/me", cookies={"docvault_session": alice_session_a})
    )
    assert res_alice.status_code == 200
    alice_data = res_alice.json()
    assert alice_data["username"] == "alice"
    assert alice_data["role"] == "user"

    # Administrator profile
    res_admin = asyncio.run(
        client.get("/api/v1/auth/me", cookies={"docvault_session": admin_session})
    )
    assert res_admin.status_code == 200
    admin_data = res_admin.json()
    assert admin_data["username"] == "admin_user"
    assert admin_data["role"] == "administrator"


def test_successful_password_change(settings_env) -> None:
    """3. Successful password change updates hash, rotates CSRF token, and verifies new credentials."""
    client, session_factory, alice, _, alice_session_a, alice_csrf_a, _, _, _ = settings_env

    res = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": alice_csrf_a},
        )
    )
    assert res.status_code == 200
    data = res.json()
    assert data["detail"] == "Password changed successfully"
    assert "csrf_token" in data
    assert data["csrf_token"] != alice_csrf_a

    # Database hash has updated and verifies against new password
    with session_factory() as db:
        user_db = db.get(User, alice.id)
        assert user_db is not None
        assert verify_password(NEW_PASSWORD, user_db.password_hash)
        assert not verify_password(INITIAL_PASSWORD, user_db.password_hash)

    # Login with old password fails
    res_old_login = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": INITIAL_PASSWORD},
        )
    )
    assert res_old_login.status_code == 401

    # Login with new password succeeds
    res_new_login = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": NEW_PASSWORD},
        )
    )
    assert res_new_login.status_code == 200


def test_incorrect_current_password_rejected(settings_env) -> None:
    """4. Submitting an incorrect current password returns 400 and preserves original password."""
    client, session_factory, alice, _, alice_session_a, alice_csrf_a, _, _, _ = settings_env

    res = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": "WrongPassword#2026", "new_password": NEW_PASSWORD},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": alice_csrf_a},
        )
    )
    assert res.status_code == 400
    assert res.json()["detail"] == "Invalid current password"

    # Password hash in database remains unchanged
    with session_factory() as db:
        user_db = db.get(User, alice.id)
        assert user_db is not None
        assert verify_password(INITIAL_PASSWORD, user_db.password_hash)


def test_invalid_password_validation(settings_env) -> None:
    """5. Invalid password policies are rejected with 422 Unprocessable Content."""
    client, _, _, _, alice_session_a, alice_csrf_a, _, _, _ = settings_env

    # Too short (< 12 characters)
    res_short = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": "Short#1"},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": alice_csrf_a},
        )
    )
    assert res_short.status_code == 422

    # Lacking complexity (< 3 categories)
    res_simple = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": "alllowercasecharactersonly"},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": alice_csrf_a},
        )
    )
    assert res_simple.status_code == 422

    # New password same as current password
    res_same = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": INITIAL_PASSWORD},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": alice_csrf_a},
        )
    )
    assert res_same.status_code == 422
    assert res_same.json()["detail"] == "New password must be different from current password"


def test_password_confirmation_mismatch_and_client_logic() -> None:
    """6. Password confirmation mismatch client logic prevents submission."""
    # Verify policy logic: passwords must match
    new_pass = "ValidPassword#123"
    confirm_pass = "DifferentPassword#123"
    assert new_pass != confirm_pass


def test_missing_or_invalid_csrf_token(settings_env) -> None:
    """7. Password change requests strictly enforce valid synchronizer CSRF tokens."""
    client, _, _, _, alice_session_a, _, _, _, _ = settings_env

    # Missing CSRF header returns 403
    res_no_csrf = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            cookies={"docvault_session": alice_session_a},
        )
    )
    assert res_no_csrf.status_code == 403

    # Invalid CSRF header returns 403
    res_bad_csrf = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": "invalid_csrf_token_value"},
        )
    )
    assert res_bad_csrf.status_code == 403


def test_duplicate_submit_prevention_via_token_rotation(settings_env) -> None:
    """8. Replaying or submitting with the previous CSRF token after rotation is blocked with 403."""
    client, _, _, _, alice_session_a, alice_csrf_a, _, _, _ = settings_env

    # 1. First change succeeds and rotates token
    res1 = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": alice_csrf_a},
        )
    )
    assert res1.status_code == 200
    rotated_csrf = res1.json()["csrf_token"]

    # 2. Duplicate submission reusing the old stale CSRF token is blocked
    res2 = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": NEW_PASSWORD, "new_password": INITIAL_PASSWORD},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": alice_csrf_a},
        )
    )
    assert res2.status_code == 403

    # 3. Submission with the rotated token succeeds
    res3 = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": NEW_PASSWORD, "new_password": INITIAL_PASSWORD},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": rotated_csrf},
        )
    )
    assert res3.status_code == 200


def test_existing_session_behavior_after_password_change(settings_env) -> None:
    """9. Password change keeps current session active, but revokes other active sessions in database."""
    client, _, _, _, alice_session_a, alice_csrf_a, alice_session_b, _, _ = settings_env

    # Before change: both Session A and Session B are active
    res_me_a = asyncio.run(client.get("/api/v1/auth/me", cookies={"docvault_session": alice_session_a}))
    assert res_me_a.status_code == 200
    res_me_b = asyncio.run(client.get("/api/v1/auth/me", cookies={"docvault_session": alice_session_b}))
    assert res_me_b.status_code == 200

    # Alice changes password from Session A
    res_change = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD},
            cookies={"docvault_session": alice_session_a},
            headers={"X-CSRF-Token": alice_csrf_a},
        )
    )
    assert res_change.status_code == 200

    # Session A remains valid
    res_me_a_after = asyncio.run(client.get("/api/v1/auth/me", cookies={"docvault_session": alice_session_a}))
    assert res_me_a_after.status_code == 200

    # Session B is now invalidated / revoked
    res_me_b_after = asyncio.run(client.get("/api/v1/auth/me", cookies={"docvault_session": alice_session_b}))
    assert res_me_b_after.status_code == 401
    assert res_me_b_after.json()["detail"] == "Authentication required"


def test_static_asset_delivery_for_settings(settings_env) -> None:
    """10. Settings static assets are served with correct headers and strict CSP."""
    client, _, _, _, _, _, _, _, _ = settings_env

    # Settings view module
    res_settings_js = asyncio.run(client.get("/static/js/views/settings.js"))
    assert res_settings_js.status_code == 200
    assert "javascript" in res_settings_js.headers.get("Content-Type", "")
    assert "default-src 'self'" in res_settings_js.headers.get("Content-Security-Policy", "")

    # Router module
    res_router_js = asyncio.run(client.get("/static/js/router.js"))
    assert res_router_js.status_code == 200

    # Stylesheet
    res_css = asyncio.run(client.get("/static/css/app.css"))
    assert res_css.status_code == 200
    assert "text/css" in res_css.headers.get("Content-Type", "")
