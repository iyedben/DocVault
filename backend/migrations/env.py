"""Alembic environment using the configured application or migration DB role."""

from alembic import context
from app.core.config import DatabaseSettings
from app.db.base import Base
from app.db.session import build_database_url
from app.models import AuthSession, Role, User  # noqa: F401
from sqlalchemy import Connection, create_engine

config = context.config
target_metadata = Base.metadata


def run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    url = build_database_url(DatabaseSettings.from_environment())
    context.configure(
        url=url.render_as_string(hide_password=True),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        run_migrations(supplied_connection)
        return

    engine = create_engine(build_database_url(DatabaseSettings.from_environment()), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            run_migrations(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
