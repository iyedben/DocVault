"""Authentication and authorization dependencies for API routes."""

import hmac
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.audit import record_security_event
from app.core.config import AuthSettings
from app.db.session import get_db
from app.models import AuthSession, User
from app.models.user import utcnow
from app.security.sessions import AuthContext, ensure_utc
from app.security.tokens import hash_token


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _unauthorized(reason: str, request: Request, actor_id: str | None = None) -> HTTPException:
    record_security_event(
        "authorization.denied",
        "denied",
        actor_id=actor_id,
        source_ip=_source_ip(request),
        reason=reason,
    )
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def get_current_auth(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> AuthContext:
    settings = AuthSettings.from_environment()
    session_token = request.cookies.get("docvault_session")
    if not session_token:
        raise _unauthorized("missing_session", request)

    auth_session = db.scalar(
        select(AuthSession)
        .options(joinedload(AuthSession.user).joinedload(User.role))
        .where(AuthSession.session_token_hash == hash_token(session_token))
    )
    if auth_session is None:
        raise _unauthorized("unknown_session", request)

    user = auth_session.user
    now = utcnow()
    expired = ensure_utc(auth_session.expires_at) <= now
    inactive = now - ensure_utc(auth_session.last_activity_at) >= timedelta(
        seconds=settings.idle_timeout_seconds
    )
    if auth_session.revoked_at is not None or expired or inactive or not user.is_active:
        if auth_session.revoked_at is None:
            auth_session.revoked_at = now
            db.commit()
        reason = "inactive_account" if not user.is_active else "expired_or_revoked_session"
        raise _unauthorized(reason, request, str(user.id))

    auth_session.last_activity_at = now
    db.commit()
    return AuthContext(user=user, auth_session=auth_session)


def require_csrf(
    request: Request,
    auth: Annotated[AuthContext, Depends(get_current_auth)],
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> AuthContext:
    expected_hash = auth.auth_session.csrf_token_hash
    provided_hash = hash_token(csrf_token) if csrf_token else ""
    if not csrf_token or not hmac.compare_digest(expected_hash, provided_hash):
        record_security_event(
            "authorization.denied",
            "denied",
            actor_id=str(auth.user.id),
            source_ip=_source_ip(request),
            reason="csrf_validation_failed",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    return auth


def require_admin(auth: Annotated[AuthContext, Depends(get_current_auth)], request: Request) -> AuthContext:
    if auth.user.role.name != "administrator":
        record_security_event(
            "authorization.denied",
            "denied",
            actor_id=str(auth.user.id),
            source_ip=_source_ip(request),
            reason="administrator_required",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access required")
    return auth


def require_admin_csrf(
    request: Request,
    auth: Annotated[AuthContext, Depends(require_admin)],
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> AuthContext:
    expected_hash = auth.auth_session.csrf_token_hash
    provided_hash = hash_token(csrf_token) if csrf_token else ""
    if not csrf_token or not hmac.compare_digest(expected_hash, provided_hash):
        record_security_event(
            "authorization.denied",
            "denied",
            actor_id=str(auth.user.id),
            source_ip=_source_ip(request),
            reason="csrf_validation_failed",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    return auth
