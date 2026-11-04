"""Process liveness and database readiness endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db

router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK)
def health() -> dict[str, str]:
    """Report that the API process is serving requests."""
    return {"status": "ok"}


@router.get("/ready", status_code=status.HTTP_200_OK)
def ready(session: Annotated[Session, Depends(get_db)]) -> dict[str, str]:
    """Report readiness only when a lightweight database query succeeds."""
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc
    return {"status": "ready"}
