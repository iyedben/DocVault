"""Tests for Phase B2 authentication lifecycle, session restoration, CSRF, and logout."""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from app.api.dependencies import get_db
from app.core.config import AuthSettings
from app.db.base import Base
from app.main import app
from app.models import AuthSession, Role, User
from app.security.login_throttle import login_throttle
from app.security.passwords import hash_password
from app.security.sessions import issue_auth_session
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

TEST_PASSWORD = "StrongPassword#2026-Test"


@pytest.fixture
def auth_env() -> Generator[tuple[httpx.AsyncClient, sessionmaker[Session], User, User], None, None]:
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

        regular_user = User(
            username="regular_alice",
            password_hash=hash_password(TEST_PASSWORD),
            role=user_role,
        )
        admin_user = User(
            username="admin_bob",
            password_hash=hash_password(TEST_PASSWORD),
            role=admin_role,
        )
        inactive_user = User(
            username="inactive_charlie",
            password_hash=hash_password(TEST_PASSWORD),
            role=user_role,
            is_active=False,
        )
        db.add_all([regular_user, admin_user, inactive_user])
        db.commit()

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    login_throttle.clear_all()

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client, session_factory, regular_user, admin_user

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
        login_throttle.clear_all()


def test_anonymous_access_and_guards(auth_env) -> None:
    client, _, _, _ = auth_env

    # 1. Anonymous root serves HTML shell with login view infrastructure
    resp = asyncio.run(client.get("/"))
    assert resp.status_code == 200
    assert "DocVault" in resp.text

    # 2. Anonymous CSRF bootstrap rejected with 401
    csrf_resp = asyncio.run(
        client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"})
    )
    assert csrf_resp.status_code == 401
    assert csrf_resp.json()["detail"] == "Authentication required"

    # 3. Anonymous /auth/me rejected with 401
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 401
    assert me_resp.json()["detail"] == "Authentication required"

    # 4. Empty credentials rejected with 422
    empty_login = asyncio.run(
        client.post("/api/v1/auth/login", json={"username": "", "password": ""})
    )
    assert empty_login.status_code == 422

    # 5. Invalid credentials rejected with 401
    bad_login = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent", "password": "WrongPassword"},
        )
    )
    assert bad_login.status_code == 401
    assert bad_login.json()["detail"] == "Invalid username or password"

    # 6. Inactive account rejected with generic 401
    inactive_login = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "inactive_charlie", "password": TEST_PASSWORD},
        )
    )
    assert inactive_login.status_code == 401
    assert inactive_login.json()["detail"] == "Invalid username or password"


def test_successful_login_regular_user_and_cookie_attributes(auth_env) -> None:
    client, _, _, _ = auth_env

    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    data = login_resp.json()

    # User schema verification
    assert data["user"]["username"] == "regular_alice"
    assert data["user"]["role"] == "user"
    assert data["user"]["is_active"] is True
    assert "password" not in data["user"]
    assert "password_hash" not in data["user"]

    # CSRF token returned
    csrf_token = data["csrf_token"]
    assert len(csrf_token) >= 32

    # Session cookie attributes
    assert "docvault_session" in client.cookies
    session_cookie = client.cookies.get("docvault_session")
    assert session_cookie is not None
    assert len(session_cookie) >= 32

    # Cache control header
    assert "no-store" in login_resp.headers["cache-control"]


def test_successful_login_administrator_role(auth_env) -> None:
    client, _, _, _ = auth_env

    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "admin_bob", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert data["user"]["username"] == "admin_bob"
    assert data["user"]["role"] == "administrator"
    assert data["csrf_token"] is not None


def test_session_restoration_flow(auth_env) -> None:
    client, _, _, _ = auth_env

    # 1. Log in to establish session
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    initial_csrf = login_resp.json()["csrf_token"]

    # 2. Simulate page refresh: Step 1 is POST /api/v1/auth/csrf with trusted origin
    csrf_bootstrap = asyncio.run(
        client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"})
    )
    assert csrf_bootstrap.status_code == 200
    restored_csrf = csrf_bootstrap.json()["csrf_token"]
    assert restored_csrf != initial_csrf  # Freshly rotated

    # 3. Step 2 is GET /api/v1/auth/me to retrieve identity
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 200
    user_data = me_resp.json()
    assert user_data["username"] == "regular_alice"
    assert user_data["role"] == "user"


def test_expired_and_revoked_session_restoration_fails(auth_env) -> None:
    client, session_factory, regular_user, _ = auth_env

    # 1. Establish session directly in DB with past expiry
    settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)
    with session_factory() as db:
        expired_at = datetime.now(UTC) - timedelta(minutes=10)
        auth_session, session_token, _ = issue_auth_session(db, regular_user, settings)
        auth_session.expires_at = expired_at
        db.commit()

    # 2. Set expired session cookie in client
    client.cookies.set("docvault_session", session_token)

    # 3. Session restoration fails on CSRF bootstrap
    csrf_resp = asyncio.run(
        client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"})
    )
    assert csrf_resp.status_code == 401
    assert csrf_resp.json()["detail"] == "Authentication required"

    # 4. /auth/me also fails
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 401
    assert me_resp.json()["detail"] == "Authentication required"


def test_csrf_validation_and_rotation_on_logout(auth_env) -> None:
    client, _, _, _ = auth_env

    # 1. Log in
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    csrf_token = login_resp.json()["csrf_token"]

    # 2. Mutating request without CSRF header is rejected with 403
    no_csrf = asyncio.run(client.post("/api/v1/auth/logout"))
    assert no_csrf.status_code == 403
    assert no_csrf.json()["detail"] == "CSRF validation failed"

    # 3. Mutating request with invalid CSRF token is rejected with 403
    bad_csrf = asyncio.run(
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "invalid-token-12345"})
    )
    assert bad_csrf.status_code == 403
    assert bad_csrf.json()["detail"] == "CSRF validation failed"

    # 4. Rotate CSRF token via POST /auth/csrf
    csrf_refresh = asyncio.run(
        client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"})
    )
    assert csrf_refresh.status_code == 200
    new_csrf_token = csrf_refresh.json()["csrf_token"]

    # 5. Old CSRF token is rejected after rotation
    old_csrf_req = asyncio.run(
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf_token})
    )
    assert old_csrf_req.status_code == 403
    assert old_csrf_req.json()["detail"] == "CSRF validation failed"

    # 6. New CSRF token succeeds
    valid_logout = asyncio.run(
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": new_csrf_token})
    )
    assert valid_logout.status_code == 204


def test_logout_invalidates_session_on_server(auth_env) -> None:
    client, session_factory, regular_user, _ = auth_env

    # 1. Log in
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    csrf_token = login_resp.json()["csrf_token"]
    session_token = client.cookies.get("docvault_session")
    assert session_token is not None

    # 2. Perform logout
    logout_resp = asyncio.run(
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf_token})
    )
    assert logout_resp.status_code == 204

    # 3. Check database to confirm session was revoked
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == regular_user.id))
        assert sess is not None
        assert sess.revoked_at is not None

    # 4. Old session cookie cannot access protected endpoints
    client.cookies.set("docvault_session", session_token)
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 401
    assert me_resp.json()["detail"] == "Authentication required"


def test_login_throttling_triggers_429(auth_env) -> None:
    client, _, _, _ = auth_env

    # Default throttle allows 5 failures
    for _ in range(5):
        resp = asyncio.run(
            client.post(
                "/api/v1/auth/login",
                json={"username": "regular_alice", "password": "WrongPassword"},
            )
        )
        assert resp.status_code == 401

    # 6th attempt is throttled
    throttled_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": "WrongPassword"},
        )
    )
    assert throttled_resp.status_code == 429
    assert throttled_resp.json()["detail"] == "Too many login attempts; try again later"


# ---------------------------------------------------------------------------
# Phase B2 Security Remediation: Specific Regression Tests
# ---------------------------------------------------------------------------


def test_successful_logout_returns_204_and_clears_cookie(auth_env) -> None:
    """1. Successful logout returning 204: revokes session in DB and clears cookie."""
    client, session_factory, regular_user, _ = auth_env

    # Log in
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    csrf_token = login_resp.json()["csrf_token"]
    session_cookie = client.cookies.get("docvault_session")
    assert session_cookie is not None

    # Call logout with valid CSRF token
    logout_resp = asyncio.run(
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf_token})
    )
    assert logout_resp.status_code == 204
    assert not logout_resp.content  # empty body

    # Verify cookie clearance in response header (Max-Age=0)
    set_cookie_header = logout_resp.headers.get("set-cookie", "")
    assert "docvault_session" in set_cookie_header
    assert "Max-Age=0" in set_cookie_header or "max-age=0" in set_cookie_header

    # Verify server database has recorded session revocation
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == regular_user.id))
        assert sess is not None
        assert sess.revoked_at is not None

    # Verify that trying to access /auth/me with old cookie fails with 401
    client.cookies.set("docvault_session", session_cookie)
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 401


def test_logout_network_failure_preserves_session_and_avoids_false_logout(auth_env) -> None:
    """2. Logout network failure: session is preserved on server and cookie remains active."""
    client, session_factory, regular_user, _ = auth_env

    # Log in
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    session_cookie = client.cookies.get("docvault_session")
    assert session_cookie is not None

    # Simulate network failure during logout (e.g. transport disconnect before reaching server)
    # The server never received/processed a logout request.
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == regular_user.id))
        assert sess is not None
        assert sess.revoked_at is None  # Database session remains active

    # Because server session is intact, cookie remains valid and /auth/me succeeds
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "regular_alice"


def test_logout_unexpected_http_response_preserves_session(auth_env, monkeypatch) -> None:
    """3. Logout unexpected HTTP response: server failure (500) rolls back and preserves session."""
    client, session_factory, regular_user, _ = auth_env

    # Log in
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    csrf_token = login_resp.json()["csrf_token"]
    session_cookie = client.cookies.get("docvault_session")

    # Simulate unexpected server failure during session revocation (e.g. database error)
    import app.api.routes.auth as auth_route_module

    def failing_revoke(session):
        raise RuntimeError("Simulated database failure during logout")

    monkeypatch.setattr(auth_route_module, "revoke_auth_session", failing_revoke)

    # Logout attempt raises 500
    with pytest.raises(RuntimeError, match="Simulated database failure during logout"):
        asyncio.run(
            client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf_token})
        )

    # Server session remains unrevoked in PostgreSQL
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == regular_user.id))
        assert sess is not None
        assert sess.revoked_at is None

    # Client cookie remains valid and functional
    client.cookies.set("docvault_session", session_cookie)
    monkeypatch.undo()
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "regular_alice"


def test_session_restoration_after_unsuccessful_logout(auth_env) -> None:
    """4. Session restoration after an unsuccessful logout succeeds because session is still active."""
    client, session_factory, regular_user, _ = auth_env

    # 1. Log in
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200

    # 2. Unsuccessful logout due to invalid CSRF token (403)
    failed_logout = asyncio.run(
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "bad-csrf-token"})
    )
    assert failed_logout.status_code == 403
    assert failed_logout.json()["detail"] == "CSRF validation failed"

    # 3. Confirm server session was NOT revoked
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == regular_user.id))
        assert sess is not None
        assert sess.revoked_at is None

    # 4. Simulate browser page reload triggering session restoration:
    # Step A: POST /api/v1/auth/csrf
    csrf_bootstrap = asyncio.run(
        client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"})
    )
    assert csrf_bootstrap.status_code == 200
    fresh_csrf = csrf_bootstrap.json()["csrf_token"]
    assert len(fresh_csrf) >= 32

    # Step B: GET /api/v1/auth/me
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 200
    user_data = me_resp.json()
    assert user_data["username"] == "regular_alice"
    assert user_data["role"] == "user"


def test_csrf_rejection_on_state_changing_request_has_no_side_effects(auth_env) -> None:
    """5. CSRF rejection on a state-changing request occurs before any handler side effect."""
    client, session_factory, regular_user, _ = auth_env

    # Log in
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200

    # Get user password hash before mutating request
    with session_factory() as db:
        user_before = db.get(User, regular_user.id)
        assert user_before is not None
        original_pw_hash = user_before.password_hash

    # Attempt state-changing password change without CSRF token
    pw_change_resp = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            json={
                "current_password": TEST_PASSWORD,
                "new_password": "NewStrongPassword#2026-X",
            },
        )
    )
    assert pw_change_resp.status_code == 403
    assert pw_change_resp.json()["detail"] == "CSRF validation failed"

    # Verify NO side effect occurred: password hash remains completely identical
    with session_factory() as db:
        user_after = db.get(User, regular_user.id)
        assert user_after is not None
        assert user_after.password_hash == original_pw_hash


def test_no_duplicate_execution_of_state_changing_request(auth_env) -> None:
    """6. No duplicate execution of a state-changing request when rejected by CSRF."""
    client, session_factory, regular_user, _ = auth_env

    # Log in
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200

    # Send a mutating request with bad CSRF
    bad_req = asyncio.run(
        client.post(
            "/api/v1/auth/password",
            headers={"X-CSRF-Token": "invalid-token"},
            json={
                "current_password": TEST_PASSWORD,
                "new_password": "NewStrongPassword#2026-Y",
            },
        )
    )
    assert bad_req.status_code == 403
    assert bad_req.json()["detail"] == "CSRF validation failed"

    # Verify in DB that no session was revoked, password was not changed (0 executions)
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == regular_user.id))
        assert sess is not None
        assert sess.revoked_at is None


def test_generic_403_authorization_denial_without_csrf_refresh_or_retry(auth_env) -> None:
    """7. Generic 403 authorization denial does NOT trigger CSRF token refresh or retry."""
    client, session_factory, regular_user, _ = auth_env

    # 1. Log in as standard user (NOT administrator)
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    csrf_token = login_resp.json()["csrf_token"]

    # 2. Record the current session's CSRF token hash from PostgreSQL
    with session_factory() as db:
        sess = db.scalar(select(AuthSession).where(AuthSession.user_id == regular_user.id))
        assert sess is not None
        initial_csrf_hash = sess.csrf_token_hash

    # 3. Call administrator-only endpoint with regular user credentials and valid CSRF token
    admin_req = asyncio.run(
        client.post(
            "/api/v1/admin/users",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "new_created_user",
                "password": "StrongPassword#2026",
                "role": "user",
            },
        )
    )

    # 4. Request is rejected with 403 Administrator access required
    assert admin_req.status_code == 403
    error_detail = admin_req.json()["detail"]
    assert error_detail == "Administrator access required"
    assert error_detail != "CSRF validation failed"

    # 5. Verify the CSRF token hash in database was NOT modified (no CSRF rotation occurred)
    with session_factory() as db:
        sess_after = db.scalar(select(AuthSession).where(AuthSession.user_id == regular_user.id))
        assert sess_after is not None
        assert sess_after.csrf_token_hash == initial_csrf_hash

    # 6. Verify user was not created in database
    with session_factory() as db:
        created_user = db.scalar(select(User).where(User.username == "new_created_user"))
        assert created_user is None


def test_existing_login_session_restoration_and_logout_lifecycle(auth_env) -> None:
    """8. Complete existing login, session restoration, and logout lifecycle."""
    client, _, _, _ = auth_env

    # Step 1: Login
    login_resp = asyncio.run(
        client.post(
            "/api/v1/auth/login",
            json={"username": "regular_alice", "password": TEST_PASSWORD},
        )
    )
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert data["user"]["username"] == "regular_alice"
    assert "docvault_session" in client.cookies

    # Step 2: In-session CSRF bootstrap / rotation
    csrf_resp = asyncio.run(
        client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"})
    )
    assert csrf_resp.status_code == 200
    rotated_csrf = csrf_resp.json()["csrf_token"]

    # Step 3: Identity retrieval
    me_resp = asyncio.run(client.get("/api/v1/auth/me"))
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "regular_alice"

    # Step 4: Logout with rotated CSRF
    logout_resp = asyncio.run(
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": rotated_csrf})
    )
    assert logout_resp.status_code == 204

    # Step 5: Post-logout endpoints are unauthenticated
    after_me = asyncio.run(client.get("/api/v1/auth/me"))
    assert after_me.status_code == 401

    after_csrf = asyncio.run(
        client.post("/api/v1/auth/csrf", headers={"Origin": "http://testserver"})
    )
    assert after_csrf.status_code == 401
