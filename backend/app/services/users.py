"""User creation and administrator lifecycle protections."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.models import Role, User
from app.security.identities import normalize_username, valid_username
from app.security.passwords import hash_password

ADMIN_ROSTER_LOCK_ID = 7_421_991


class DuplicateUsernameError(ValueError):
    """Raised when a normalized username already exists."""


class InitialAdminExistsError(ValueError):
    """Raised when an administrator is already present."""


class RoleConfigurationError(RuntimeError):
    """Raised when a required role record has not been migrated into the DB."""


def get_role(session: Session, name: str) -> Role:
    role = session.scalar(select(Role).where(Role.name == name))
    if role is None:
        raise RoleConfigurationError("Role records are missing; run database migrations")
    return role


def create_user(
    session: Session,
    username: str,
    password: str,
    role_name: str = "user",
) -> User:
    normalized = normalize_username(username)
    if not valid_username(normalized):
        raise ValueError("Username must be 3–32 lowercase letters, digits, dots, underscores or hyphens")
    if role_name not in {"user", "administrator"}:
        raise ValueError("Requested role is not allowed")
    role = get_role(session, role_name)
    if session.scalar(select(User.id).where(User.username == normalized)) is not None:
        raise DuplicateUsernameError("Username already exists")

    user = User(username=normalized, password_hash=hash_password(password), role=role)
    session.add(user)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise DuplicateUsernameError("Username already exists") from exc
    return user


def lock_active_admin_roster(session: Session) -> None:
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": ADMIN_ROSTER_LOCK_ID})


def active_admin_count(session: Session) -> int:
    count = session.scalar(
        select(func.count(User.id))
        .join(Role, User.role_id == Role.id)
        .where(User.is_active.is_(True), Role.name == "administrator")
    )
    return int(count or 0)


def bootstrap_first_admin(session: Session, username: str, password: str) -> User:
    lock_active_admin_roster(session)
    if session.scalar(select(User.id).join(Role).where(Role.name == "administrator")) is not None:
        session.rollback()
        raise InitialAdminExistsError("An administrator already exists; bootstrap refused")
    admin = create_user(session, username, password, "administrator")
    session.commit()
    session.refresh(admin)
    return admin


def change_user_role(session: Session, user: User, role_name: str) -> None:
    lock_active_admin_roster(session)
    session.refresh(user)
    session.expire(user, ["role"])
    if role_name not in {"user", "administrator"}:
        raise ValueError("Requested role is not allowed")
    current_role = user.role.name
    if (
        user.is_active
        and current_role == "administrator"
        and role_name != "administrator"
        and active_admin_count(session) <= 1
    ):
        session.rollback()
        raise ValueError("The final active administrator cannot be demoted")
    user.role = get_role(session, role_name)
    session.commit()


def change_user_active_status(session: Session, user: User, is_active: bool) -> None:
    lock_active_admin_roster(session)
    session.refresh(user)
    session.expire(user, ["role"])
    if (
        user.is_active
        and not is_active
        and user.role.name == "administrator"
        and active_admin_count(session) <= 1
    ):
        session.rollback()
        raise ValueError("The final active administrator cannot be deactivated")
    user.is_active = is_active
    if not is_active:
        for auth_session in user.sessions:
            if auth_session.revoked_at is None:
                auth_session.revoked_at = datetime.now(UTC)
    session.commit()


def get_user(session: Session, user_id: uuid.UUID) -> User | None:
    return session.scalar(
        select(User).options(joinedload(User.role)).where(User.id == user_id)
    )
