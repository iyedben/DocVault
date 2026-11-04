"""Server-side session creation and opaque token operations."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import AuthSettings
from app.models import AuthSession, User
from app.models.user import utcnow
from app.security.tokens import generate_opaque_token, hash_token

SESSION_COOKIE_NAME = "docvault_session"
SESSION_COOKIE_PATH = "/api/v1"


@dataclass(frozen=True, slots=True)
class AuthContext:
    user: User
    auth_session: AuthSession


def issue_auth_session(
    db: Session,
    user: User,
    settings: AuthSettings,
    *,
    now: datetime | None = None,
) -> tuple[AuthSession, str, str]:
    created_at = now or utcnow()
    session_token = generate_opaque_token()
    csrf_token = generate_opaque_token()
    auth_session = AuthSession(
        session_token_hash=hash_token(session_token),
        csrf_token_hash=hash_token(csrf_token),
        user=user,
        created_at=created_at,
        last_activity_at=created_at,
        expires_at=created_at + timedelta(seconds=settings.session_ttl_seconds),
    )
    db.add(auth_session)
    return auth_session, session_token, csrf_token


def find_session_by_token(db: Session, session_token: str) -> AuthSession | None:
    return db.scalar(select(AuthSession).where(AuthSession.session_token_hash == hash_token(session_token)))


def revoke_auth_session(auth_session: AuthSession, *, now: datetime | None = None) -> None:
    if auth_session.revoked_at is None:
        auth_session.revoked_at = now or utcnow()


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
