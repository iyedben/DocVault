"""Administrator-protected user management endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.api.dependencies import require_admin, require_admin_csrf
from app.api.routes.auth import safe_user
from app.api.schemas import (
    CreateUserRequest,
    SafeUser,
    UserRoleRequest,
    UserStatusRequest,
)
from app.audit import record_security_event
from app.core.config import AuthSettings
from app.db.session import get_db
from app.models import User
from app.security.sessions import SESSION_COOKIE_NAME, SESSION_COOKIE_PATH, AuthContext
from app.services.users import (
    DuplicateUsernameError,
    change_user_active_status,
    change_user_role,
    create_user,
    get_user,
)

router = APIRouter(prefix="/api/v1/admin/users", tags=["user administration"])


def _source_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("", response_model=list[SafeUser])
def list_users(
    _admin: Annotated[AuthContext, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
) -> list[SafeUser]:
    users = db.scalars(select(User).options(joinedload(User.role)).order_by(User.username)).all()
    return [safe_user(user) for user in users]


@router.post("", response_model=SafeUser, status_code=status.HTTP_201_CREATED)
def create_managed_user(
    payload: CreateUserRequest,
    request: Request,
    _admin: Annotated[AuthContext, Depends(require_admin_csrf)],
    db: Annotated[Session, Depends(get_db)],
) -> SafeUser:
    try:
        user = create_user(
            db,
            payload.username,
            payload.password.get_secret_value(),
            payload.role,
        )
    except DuplicateUsernameError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists") from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    db.refresh(user)
    record_security_event(
        "admin.user_created",
        "success",
        actor_id=str(_admin.user.id),
        target_id=str(user.id),
        source_ip=_source_ip(request),
        reason=f"assigned_role:{payload.role}",
    )
    return safe_user(user)


@router.patch("/{user_id}/status", response_model=SafeUser)
def set_user_status(
    user_id: UUID,
    payload: UserStatusRequest,
    request: Request,
    response: Response,
    admin: Annotated[AuthContext, Depends(require_admin_csrf)],
    db: Annotated[Session, Depends(get_db)],
) -> SafeUser:
    user = get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    try:
        change_user_active_status(db, user, payload.is_active)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if not payload.is_active:
        event = "admin.user_deactivated"
    else:
        event = "admin.user_reactivated"
    if user.id == admin.user.id and not payload.is_active:
        response.delete_cookie(
            key=SESSION_COOKIE_NAME,
            path=SESSION_COOKIE_PATH,
            secure=AuthSettings.from_environment().cookie_secure,
            httponly=True,
            samesite="lax",
        )
    record_security_event(
        event,
        "success",
        actor_id=str(admin.user.id),
        target_id=str(user.id),
        source_ip=_source_ip(request),
    )
    return safe_user(user)


@router.patch("/{user_id}/role", response_model=SafeUser)
def set_user_role(
    user_id: UUID,
    payload: UserRoleRequest,
    request: Request,
    admin: Annotated[AuthContext, Depends(require_admin_csrf)],
    db: Annotated[Session, Depends(get_db)],
) -> SafeUser:
    user = get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    old_role = user.role.name
    try:
        change_user_role(db, user, payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    record_security_event(
        "admin.user_role_changed",
        "success",
        actor_id=str(admin.user.id),
        target_id=str(user.id),
        source_ip=_source_ip(request),
        reason=f"{old_role}_to_{payload.role}",
    )
    return safe_user(user)
