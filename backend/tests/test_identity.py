"""Database, password, role bootstrap, and admin-integrity tests."""

import pytest
from app.core.config import AuthSettings
from app.models import AuthSession, Role, User
from app.security.passwords import PasswordPolicyError, hash_password, verify_password
from app.security.sessions import issue_auth_session
from app.services.users import (
    DuplicateUsernameError,
    InitialAdminExistsError,
    bootstrap_first_admin,
    change_user_active_status,
    change_user_role,
    create_user,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

TEST_PASSWORD = "PhaseThree-Test!2026-Strong"


def test_user_creation_normalizes_username_and_rejects_duplicate(db_session: Session) -> None:
    first = create_user(db_session, "  Alice  ", TEST_PASSWORD)
    db_session.commit()

    assert first.username == "alice"
    with pytest.raises(DuplicateUsernameError):
        create_user(db_session, "ALICE", TEST_PASSWORD)
    assert db_session.scalar(select(func.count(User.id))) == 1


def test_database_constraint_rejects_duplicate_normalized_identity(db_session: Session) -> None:
    role = db_session.scalar(select(Role).where(Role.name == "user"))
    assert role is not None
    db_session.add(User(username="same_user", password_hash="not-a-plaintext-password", role=role))
    db_session.commit()
    db_session.add(User(username="same_user", password_hash="another-hash", role=role))

    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_database_rejects_roles_outside_the_two_allowed_values(db_session: Session) -> None:
    db_session.add(Role(name="superuser"))

    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_database_rejects_non_normalized_username(db_session: Session) -> None:
    role = db_session.scalar(select(Role).where(Role.name == "user"))
    assert role is not None
    db_session.add(User(username="UpperCase", password_hash="hash-value", role=role))

    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_passwords_are_argon2id_hashed_and_verified() -> None:
    encoded = hash_password(TEST_PASSWORD)

    assert encoded.startswith("$argon2id$")
    assert encoded != TEST_PASSWORD
    assert verify_password(TEST_PASSWORD, encoded)
    assert not verify_password("Wrong-password-2026!", encoded)
    assert not verify_password(TEST_PASSWORD, None)


@pytest.mark.parametrize("password", ["short", "alllowercasepassphrase", "NoDigitsOrSymbols"])
def test_new_password_policy_rejects_weak_values(password: str) -> None:
    with pytest.raises(PasswordPolicyError):
        hash_password(password)


def test_user_record_never_persists_plaintext_password(db_session: Session) -> None:
    user = create_user(db_session, "plaincheck", TEST_PASSWORD)
    db_session.commit()
    stored = db_session.get(User, user.id)

    assert stored is not None
    assert stored.password_hash != TEST_PASSWORD
    assert TEST_PASSWORD not in stored.password_hash
    assert verify_password(TEST_PASSWORD, stored.password_hash)


def test_bootstrap_creates_only_one_initial_administrator(db_session: Session) -> None:
    admin = bootstrap_first_admin(db_session, "FirstAdmin", TEST_PASSWORD)

    assert admin.username == "firstadmin"
    assert admin.role.name == "administrator"
    with pytest.raises(InitialAdminExistsError):
        bootstrap_first_admin(db_session, "SecondAdmin", TEST_PASSWORD)
    assert db_session.scalar(
        select(func.count(User.id)).join(Role).where(Role.name == "administrator")
    ) == 1


def test_bootstrap_refuses_to_seed_default_credentials(db_session: Session) -> None:
    with pytest.raises(PasswordPolicyError):
        bootstrap_first_admin(db_session, "admin", "admin")
    assert db_session.scalar(select(func.count(User.id))) == 0


def test_final_active_administrator_cannot_be_disabled_or_demoted(db_session: Session) -> None:
    admin = create_user(db_session, "onlyadmin", TEST_PASSWORD, "administrator")
    db_session.commit()

    with pytest.raises(ValueError, match="final active administrator"):
        change_user_active_status(db_session, admin, False)
    db_session.rollback()
    with pytest.raises(ValueError, match="final active administrator"):
        change_user_role(db_session, admin, "user")
    db_session.rollback()

    assert admin.is_active
    assert admin.role.name == "administrator"


def test_admin_can_be_demoted_when_another_active_admin_exists(db_session: Session) -> None:
    first = create_user(db_session, "adminone", TEST_PASSWORD, "administrator")
    second = create_user(db_session, "admintwo", TEST_PASSWORD, "administrator")
    db_session.commit()

    change_user_role(db_session, first, "user")

    assert first.role.name == "user"
    assert second.is_active
    assert second.role.name == "administrator"


def test_deactivation_revokes_all_sessions(db_session: Session) -> None:
    user = create_user(db_session, "disableme", TEST_PASSWORD)
    db_session.commit()
    _record, _raw_session, _csrf = issue_auth_session(
        db_session,
        user,
        AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800),
    )
    db_session.commit()

    change_user_active_status(db_session, user, False)

    session_record = db_session.scalar(select(AuthSession).where(AuthSession.user_id == user.id))
    assert not user.is_active
    assert session_record is not None and session_record.revoked_at is not None
