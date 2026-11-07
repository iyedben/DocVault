"""Authentication, session, CSRF, cookie, and throttling tests."""

from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie

import pytest
from app.api.dependencies import get_current_auth, require_csrf
from app.api.routes.auth import current_user, login, logout
from app.api.schemas import CreateUserRequest, LoginRequest
from app.core.config import AuthSettings
from app.main import app, sanitized_validation_errors
from app.models import AuthSession, User
from app.security.login_throttle import LoginThrottle, login_throttle
from app.security.sessions import (
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_PATH,
    AuthContext,
    issue_auth_session,
)
from app.security.tokens import generate_opaque_token, hash_token
from app.services.users import create_user
from fastapi import HTTPException, Response
from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

TEST_PASSWORD = "PhaseThree-Test!2026-Strong"


def test_authentication_and_administration_routes_are_mounted() -> None:
    paths = app.openapi()["paths"]

    assert "post" in paths["/api/v1/auth/login"]
    assert "post" in paths["/api/v1/auth/logout"]
    assert "get" in paths["/api/v1/auth/me"]
    assert "post" in paths["/api/v1/auth/csrf"]
    assert "get" not in paths["/api/v1/auth/csrf"]
    assert "post" in paths["/api/v1/auth/password"]
    assert "get" in paths["/api/v1/users/lookup"]
    assert {"get", "post"} <= paths["/api/v1/admin/users"].keys()
    assert "patch" in paths["/api/v1/admin/users/{user_id}/status"]
    assert "patch" in paths["/api/v1/admin/users/{user_id}/role"]


def request_with_cookie(token: str | None = None, ip: str = "198.51.100.22"):
    headers = []
    if token:
        headers.append((b"cookie", f"{SESSION_COOKIE_NAME}={token}".encode()))
    return __import__("starlette.requests", fromlist=["Request"]).Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/auth/me",
            "raw_path": b"/api/v1/auth/me",
            "query_string": b"",
            "headers": headers,
            "client": (ip, 40000),
            "server": ("testserver", 8000),
        }
    )


def create_test_session(db_session: Session, user: User, *, expires_at: datetime | None = None):
    settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)
    record, raw_session, raw_csrf = issue_auth_session(db_session, user, settings)
    if expires_at is not None:
        record.expires_at = expires_at
    db_session.commit()
    return record, raw_session, raw_csrf


def test_login_sets_secure_cookie_rotates_session_and_returns_csrf(db_session: Session, monkeypatch) -> None:
    user = create_user(db_session, "loginuser", TEST_PASSWORD)
    old_session_token = generate_opaque_token()
    old_record = AuthSession(
        session_token_hash=hash_token(old_session_token),
        csrf_token_hash=hash_token(generate_opaque_token()),
        user=user,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(old_record)
    db_session.commit()
    login_throttle.clear_all()
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")

    response = Response()
    result = login(
        LoginRequest(username="LOGINUSER", password=SecretStr(TEST_PASSWORD)),
        request_with_cookie(old_session_token),
        response,
        db_session,
    )

    cookie = SimpleCookie(response.headers["set-cookie"])[SESSION_COOKIE_NAME]
    records = db_session.scalars(select(AuthSession).where(AuthSession.user_id == user.id)).all()
    new_record = next(record for record in records if record.session_token_hash == hash_token(cookie.value))

    assert response.status_code == 200
    assert cookie["httponly"]
    assert cookie["secure"]
    assert cookie["samesite"] == "lax"
    assert cookie["path"] == SESSION_COOKIE_PATH
    assert cookie.value != old_session_token
    assert old_record.revoked_at is not None
    assert new_record.session_token_hash != cookie.value
    assert new_record.csrf_token_hash == hash_token(result.csrf_token)
    assert cookie.value not in result.model_dump_json()
    assert result.user.username == "loginuser"
    assert "password_hash" not in result.user.model_dump()
    assert response.headers["cache-control"] == "no-store"


def test_login_failure_is_generic_for_wrong_or_unknown_credentials(db_session: Session) -> None:
    create_user(db_session, "knownuser", TEST_PASSWORD)
    db_session.commit()
    login_throttle.clear_all()
    response = Response()

    with pytest.raises(HTTPException) as known_failure:
        login(
            LoginRequest(username="knownuser", password=SecretStr("Wrong-Password!2026")),
            request_with_cookie(ip="198.51.100.31"),
            response,
            db_session,
        )
    with pytest.raises(HTTPException) as unknown_failure:
        login(
            LoginRequest(username="missinguser", password=SecretStr(TEST_PASSWORD)),
            request_with_cookie(ip="198.51.100.32"),
            Response(),
            db_session,
        )

    assert known_failure.value.status_code == unknown_failure.value.status_code == 401
    assert known_failure.value.detail == unknown_failure.value.detail == "Invalid username or password"


def test_inactive_account_is_rejected_with_generic_failure(db_session: Session) -> None:
    user = create_user(db_session, "inactiveuser", TEST_PASSWORD)
    user.is_active = False
    db_session.commit()
    login_throttle.clear_all()

    with pytest.raises(HTTPException) as error:
        login(
            LoginRequest(username="inactiveuser", password=SecretStr(TEST_PASSWORD)),
            request_with_cookie(),
            Response(),
            db_session,
        )

    assert error.value.status_code == 401
    assert error.value.detail == "Invalid username or password"


def test_login_throttle_returns_429_after_configured_failures(db_session: Session, monkeypatch) -> None:
    clock_value = [0.0]
    throttle = LoginThrottle(attempts=1, window_seconds=60, clock=lambda: clock_value[0])
    monkeypatch.setattr("app.api.routes.auth.login_throttle", throttle)

    with pytest.raises(HTTPException) as first:
        login(
            LoginRequest(username="unknownuser", password=SecretStr(TEST_PASSWORD)),
            request_with_cookie(),
            Response(),
            db_session,
        )
    with pytest.raises(HTTPException) as second:
        login(
            LoginRequest(username="unknownuser", password=SecretStr(TEST_PASSWORD)),
            request_with_cookie(),
            Response(),
            db_session,
        )

    assert first.value.status_code == 401
    assert second.value.status_code == 429
    clock_value[0] = 61.0
    assert not throttle.is_limited("198.51.100.22", "unknownuser")


def test_current_user_rejects_expired_session_and_revokes_it(db_session: Session) -> None:
    user = create_user(db_session, "expireduser", TEST_PASSWORD)
    db_session.commit()
    record, raw_session, _csrf = create_test_session(
        db_session,
        user,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    with pytest.raises(HTTPException) as error:
        get_current_auth(request_with_cookie(raw_session), db_session)

    assert error.value.status_code == 401
    assert record.revoked_at is not None


def test_current_user_rejects_idle_session(db_session: Session) -> None:
    user = create_user(db_session, "idleuser", TEST_PASSWORD)
    db_session.commit()
    record, raw_session, _csrf = create_test_session(db_session, user)
    record.last_activity_at = datetime.now(UTC) - timedelta(hours=1)
    db_session.commit()

    with pytest.raises(HTTPException) as error:
        get_current_auth(request_with_cookie(raw_session), db_session)

    assert error.value.status_code == 401
    assert record.revoked_at is not None


def test_csrf_token_is_required_and_validated_against_session(db_session: Session) -> None:
    user = create_user(db_session, "csrfuser", TEST_PASSWORD)
    db_session.commit()
    _record, raw_session, raw_csrf = create_test_session(db_session, user)
    auth = get_current_auth(request_with_cookie(raw_session), db_session)

    with pytest.raises(HTTPException) as missing:
        require_csrf(request_with_cookie(raw_session), auth)
    with pytest.raises(HTTPException) as invalid:
        require_csrf(request_with_cookie(raw_session), auth, "not-the-token")
    assert require_csrf(request_with_cookie(raw_session), auth, raw_csrf) is auth

    assert missing.value.status_code == invalid.value.status_code == 403


def test_logout_revokes_session_and_clears_cookie(db_session: Session) -> None:
    user = create_user(db_session, "logoutuser", TEST_PASSWORD)
    db_session.commit()
    record, raw_session, raw_csrf = create_test_session(db_session, user)
    auth = AuthContext(user=user, auth_session=record)
    require_csrf(request_with_cookie(raw_session), auth, raw_csrf)
    response = logout(Response(), auth, db_session)

    cookie = SimpleCookie(response.headers["set-cookie"])[SESSION_COOKIE_NAME]
    assert response.status_code == 204
    assert cookie.value == ""
    assert cookie["path"] == SESSION_COOKIE_PATH
    assert record.revoked_at is not None
    with pytest.raises(HTTPException):
        get_current_auth(request_with_cookie(raw_session), db_session)


def test_me_returns_only_safe_profile_and_database_role(db_session: Session) -> None:
    user = create_user(db_session, "safeprofile", TEST_PASSWORD)
    db_session.commit()
    _record, raw_session, _csrf = create_test_session(db_session, user)
    auth = get_current_auth(request_with_cookie(raw_session), db_session)
    profile = current_user(auth)

    assert profile.username == "safeprofile"
    assert profile.role == "user"
    assert "password_hash" not in profile.model_dump()
    assert "sessions" not in profile.model_dump()


def test_login_request_rejects_client_supplied_role_without_echoing_password() -> None:
    with pytest.raises(ValidationError) as error:
        LoginRequest.model_validate(
            {
                "username": "ordinaryuser",
                "password": TEST_PASSWORD,
                "role": "administrator",
            }
        )

    assert TEST_PASSWORD not in str(error.value)


def test_new_password_validation_does_not_echo_weak_password() -> None:
    weak_password = "alllowercasepassphrase"
    with pytest.raises(ValidationError) as error:
        CreateUserRequest.model_validate(
            {"username": "newperson", "password": weak_password, "role": "user"}
        )

    safe_errors = sanitized_validation_errors(error.value.errors())
    assert weak_password not in str(safe_errors)
    assert all("input" not in item and "ctx" not in item for item in safe_errors)
