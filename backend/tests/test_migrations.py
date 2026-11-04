"""SQLite verification of the initial Alembic identity migration and role seed."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from alembic import command
from alembic.config import Config
from app.models import Role
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


def test_identity_migration_creates_schema_and_idempotent_initial_roles() -> None:
    engine = create_engine("sqlite://", poolclass=StaticPool)
    revision_path = Path("backend/migrations/versions/0001_identity_sessions.py")
    spec = spec_from_file_location("identity_migration", revision_path)
    assert spec is not None and spec.loader is not None
    migration = module_from_spec(spec)
    spec.loader.exec_module(migration)

    with engine.connect() as connection:
        config = Config("alembic.ini")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        migration.seed_initial_roles(connection)
        migration.seed_initial_roles(connection)

        with Session(bind=connection) as session:
            role_names = set(session.scalars(select(Role.name)).all())

    engine.dispose()
    assert role_names == {"user", "administrator"}
