"""Tests for administrator authorization, user management, and audit output."""

import json
import logging

import pytest
from app.api.dependencies import require_admin, require_admin_csrf
from app.api.routes.admin_users import (
    create_managed_user,
    list_users,
    set_user_role,
    set_user_status,
)
from app.api.schemas import CreateUserRequest, UserRoleRequest, UserStatusRequest
from app.audit import record_security_event
from app.core.config import AuthSettings
from app.models import User
from app.security.sessions import AuthContext, issue_auth_session
from app.services.users import create_user
from fastapi import HTTPException, Response
from pydantic import SecretStr, ValidationError
from sqlalchemy.orm import Session

TEST_PASSWORD = "PhaseThree-Test!2026-Strong"


def make_request(ip: str = "198.51.100.44"):
    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/admin/users",
            "raw_path": b"/api/v1/admin/users",
            "query_string": b"",
            "headers": [],
            "client": (ip, 40000),
            "server": ("testserver", 8000),
        }
    )


def make_auth(db_session: Session, user: User) -> tuple[AuthContext, str]:
    settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)
    record, _session_token, raw_csrf = issue_auth_session(db_session, user, settings)
    db_session.commit()
    return AuthContext(user=user, auth_session=record), raw_csrf


def test_only_administrators_can_access_administration(db_session: Session) -> None:
    normal_user = create_user(db_session, "regularuser", TEST_PASSWORD)
    admin = create_user(db_session, "rootadmin", TEST_PASSWORD, "administrator")
    db_session.commit()
    user_auth, _user_csrf = make_auth(db_session, normal_user)
    admin_auth, admin_csrf = make_auth(db_session, admin)

    with pytest.raises(HTTPException) as denied:
        require_admin(user_auth, make_request())

    assert denied.value.status_code == 403
    assert require_admin(admin_auth, make_request()) is admin_auth
    assert require_admin_csrf(make_request(), admin_auth, admin_csrf) is admin_auth
    with pytest.raises(HTTPException) as csrf_denied:
        require_admin_csrf(make_request(), admin_auth)
    assert csrf_denied.value.status_code == 403


def test_admin_can_create_user_and_list_never_exposes_hash_or_sessions(db_session: Session) -> None:
    admin = create_user(db_session, "manager", TEST_PASSWORD, "administrator")
    db_session.commit()
    admin_auth, csrf = make_auth(db_session, admin)

    payload = CreateUserRequest(
        username="NewUser",
        password=SecretStr("New-User!Passphrase-2026"),
        role="user",
    )
    created = create_managed_user(payload, make_request(), admin_auth, db_session)
    users = list_users(admin_auth, db_session)

    assert created.username == "newuser"
    assert created.role == "user"
    assert len(users) == 2
    assert all("password_hash" not in user.model_dump() for user in users)
    assert all("sessions" not in user.model_dump() for user in users)
    assert csrf


def test_admin_can_assign_allowed_role_and_cannot_assign_other_values(db_session: Session) -> None:
    admin = create_user(db_session, "managerrole", TEST_PASSWORD, "administrator")
    target = create_user(db_session, "roleuser", TEST_PASSWORD)
    db_session.commit()
    admin_auth, _csrf = make_auth(db_session, admin)

    changed = set_user_role(
        target.id,
        UserRoleRequest(role="administrator"),
        make_request(),
        admin_auth,
        db_session,
    )

    assert changed.role == "administrator"
    with pytest.raises(ValidationError):
        UserRoleRequest.model_validate({"role": "superuser"})


def test_final_admin_role_change_endpoint_returns_conflict(db_session: Session) -> None:
    admin = create_user(db_session, "singleadmin", TEST_PASSWORD, "administrator")
    db_session.commit()
    admin_auth, _csrf = make_auth(db_session, admin)

    with pytest.raises(HTTPException) as error:
        set_user_role(
            admin.id,
            UserRoleRequest(role="user"),
            make_request(),
            admin_auth,
            db_session,
        )

    assert error.value.status_code == 409
    assert admin.role.name == "administrator"


def test_final_admin_self_deactivation_endpoint_returns_conflict(db_session: Session) -> None:
    admin = create_user(db_session, "singleactiveadmin", TEST_PASSWORD, "administrator")
    db_session.commit()
    admin_auth, csrf = make_auth(db_session, admin)
    csrf_auth = require_admin_csrf(make_request(), admin_auth, csrf)

    with pytest.raises(HTTPException) as error:
        set_user_status(
            admin.id,
            UserStatusRequest(is_active=False),
            make_request(),
            Response(),
            csrf_auth,
            db_session,
        )

    assert error.value.status_code == 409
    db_session.refresh(admin)
    assert admin.is_active
    assert admin.role.name == "administrator"


def test_administrative_security_log_is_structured_and_allow_listed(caplog) -> None:
    caplog.set_level(logging.INFO, logger="docvault.security")
    record_security_event(
        "auth.failure",
        "denied",
        actor_id=None,
        source_ip="198.51.100.9",
        reason="invalid_credentials",
    )
    event = json.loads(caplog.records[-1].getMessage())

    assert event["event"] == "auth.failure"
    assert event["outcome"] == "denied"
    assert event["source_ip"] == "198.51.100.9"
    assert set(event) == {"timestamp", "event", "outcome", "actor_id", "target_id", "source_ip", "reason"}
