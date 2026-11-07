"""Authenticated user lookup endpoint for sharing and directory queries."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_auth
from app.api.schemas import UserLookupResponse
from app.db.session import get_db
from app.security.sessions import AuthContext
from app.services.users import search_active_users

router = APIRouter(prefix="/api/v1/users", tags=["users"])

MIN_QUERY_LENGTH = 2
MAX_LOOKUP_RESULTS = 10


@router.get("/lookup", response_model=list[UserLookupResponse])
def lookup_users(
    username: Annotated[str, Query(min_length=MIN_QUERY_LENGTH, max_length=32, description="Username query")],
    _auth: Annotated[AuthContext, Depends(get_current_auth)],
    db: Annotated[Session, Depends(get_db)],
) -> list[UserLookupResponse]:
    """Look up active users by case-insensitive partial username match."""
    cleaned_query = username.strip()
    if len(cleaned_query) < MIN_QUERY_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Query parameter 'username' must be at least {MIN_QUERY_LENGTH} characters",
        )

    users = search_active_users(db, cleaned_query, limit=MAX_LOOKUP_RESULTS)
    return [UserLookupResponse(id=user.id, username=user.username) for user in users]
