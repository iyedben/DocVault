"""Reusable SQLAlchemy engine, session factory, and request dependency."""

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import DatabaseSettings


def build_database_url(settings: DatabaseSettings) -> URL:
    """Build a PostgreSQL URL while letting SQLAlchemy encode credentials."""
    return URL.create(
        drivername="postgresql+psycopg",
        username=settings.user,
        password=settings.password,
        host=settings.host,
        port=settings.port,
        database=settings.name,
    )


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Return the process-wide engine without opening a connection eagerly."""
    settings = DatabaseSettings.from_environment()
    return create_engine(
        build_database_url(settings),
        pool_pre_ping=True,
    )


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    """Return the process-wide ORM session factory."""
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """Yield one request-scoped session and always close it afterward."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
