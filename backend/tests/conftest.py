"""Reusable isolated SQLite fixture for identity and authentication tests."""

import os
from pathlib import Path

import pytest
from app.db.base import Base
from app.models import Role
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    """Ignore browser e2e tests during standard unit/integration test runs.

    e2e tests require a live application server and isolated database,
    invoked via scripts/run_e2e_tests.sh or explicitly with 'pytest backend/tests/e2e'.
    """
    path_str = str(collection_path)
    if "e2e" in path_str:
        if os.environ.get("DOCVAULT_E2E_ENABLE") == "1":
            return False
        # Do not ignore if e2e directory was explicitly targeted on CLI
        return not any("e2e" in str(arg) for arg in config.args)
    return None


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
