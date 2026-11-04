"""Reusable isolated SQLite fixture for identity and authentication tests."""

import pytest
from app.db.base import Base
from app.models import Role
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


@pytest.fixture
def db_session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        session.add_all([Role(name="user"), Role(name="administrator")])
        session.commit()
        yield session
    engine.dispose()
