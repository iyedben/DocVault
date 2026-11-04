"""Cookie-based login, logout, and current-user endpoints."""

from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.api.dependencies import get_current_auth, require_csrf
from app.api.schemas import LoginRequest, LoginResponse, SafeUser
from app.audit import record_security_event
from app.core.config import AuthSettings
from app.db.session import get_db
from app.models import AuthSession, User
from app.models.user import utcnow
from app.security.identities import normalize_username
from app.security.login_throttle import login_throttle
from app.security.passwords import (
    hash_password,
    password_hash_needs_rehash,
    verify_password,
)
from app.security.sessions import (
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_PATH,
    AuthContext,
    issue_auth_session,
    revoke_auth_session,
)
from app.security.tokens import hash_token

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


def _source_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def safe_user(user: User) -> SafeUser:
    role_name = cast(Literal["user", "administrator"], user.role.name)
    return SafeUser(
        id=user.id,
        username=user.username,
        role=role_name,
        is_active=user.is_active,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> LoginResponse:
    username = normalize_username(payload.username)
    password = payload.password.get_secret_value()
    source_ip = _source_ip(request)
    settings = AuthSettings.from_environment()

    if login_throttle.is_limited(source_ip, username):
        record_security_event("auth.throttled", "denied", source_ip=source_ip, reason="rate_limit")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts; try again later",
        )

    user = db.scalar(select(User).options(joinedload(User.role)).where(User.username == username))
    password_valid = verify_password(password, user.password_hash if user else None)
    if user is None or not password_valid or not user.is_active:
        login_throttle.record_failure(source_ip, username)
        record_security_event("auth.failure", "denied", source_ip=source_ip, reason="invalid_credentials")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    login_throttle.clear(source_ip, username)
    if password_hash_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    old_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if old_cookie:
        old_session = db.scalar(
            select(AuthSession).where(AuthSession.session_token_hash == hash_token(old_cookie))
        )
        if old_session is not None:
            revoke_auth_session(old_session)

    now = utcnow()
    _auth_session, session_token, csrf_token = issue_auth_session(db, user, settings, now=now)
    db.commit()

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=settings.session_ttl_seconds,
        path=SESSION_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
    record_security_event("auth.success", "success", actor_id=str(user.id), source_ip=source_ip)
    return LoginResponse(user=safe_user(user), csrf_token=csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    auth: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    revoke_auth_session(auth.auth_session)
    db.commit()
    settings = AuthSettings.from_environment()
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path=SESSION_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
    response.status_code = status.HTTP_204_NO_CONTENT
    record_security_event("auth.logout", "success", actor_id=str(auth.user.id))
    return response


@router.get("/me", response_model=SafeUser)
def current_user(auth: Annotated[AuthContext, Depends(get_current_auth)]) -> SafeUser:
    return safe_user(auth.user)
