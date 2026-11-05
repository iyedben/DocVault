"""SQLite migration tests for document metadata and shares."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool


def test_document_migration_upgrade_and_downgrade_only_changes_new_objects() -> None:
    engine = create_engine("sqlite://", poolclass=StaticPool)
    config = Config("alembic.ini")

    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001_identity_sessions")
        before_tables = set(inspect(connection).get_table_names())
        assert {"roles", "users", "auth_sessions"} <= before_tables
        assert {"documents", "document_shares"}.isdisjoint(before_tables)
        seeded_roles = set(connection.execute(text("SELECT name FROM roles")).scalars())
        assert seeded_roles == {"user", "administrator"}

        command.upgrade(config, "head")
        upgraded = inspect(connection)
        assert {"documents", "document_shares"} <= set(upgraded.get_table_names())
        assert {"roles", "users", "auth_sessions"} <= set(upgraded.get_table_names())

        document_checks = {
            item["name"] for item in upgraded.get_check_constraints("documents")
        }
        assert document_checks == {
            "ck_documents_media_type_pdf",
            "ck_documents_file_size_range",
            "ck_documents_status_allowed",
            "ck_documents_display_filename_length",
        }
        document_uniques = {
            tuple(item["column_names"])
            for item in upgraded.get_unique_constraints("documents")
        }
        assert ("storage_key",) in document_uniques

        document_indexes = {item["name"] for item in upgraded.get_indexes("documents")}
        assert document_indexes == {"ix_documents_owner_status", "ix_documents_status"}
        share_indexes = {
            item["name"] for item in upgraded.get_indexes("document_shares")
        }
        assert share_indexes == {"ix_document_shares_recipient_user_id"}

        share_uniques = {
            tuple(item["column_names"])
            for item in upgraded.get_unique_constraints("document_shares")
        }
        assert ("document_id", "recipient_user_id") in share_uniques

        document_fks = upgraded.get_foreign_keys("documents")
        assert document_fks[0]["options"]["ondelete"] == "RESTRICT"
        share_fks = upgraded.get_foreign_keys("document_shares")
        assert all(item["options"]["ondelete"] == "RESTRICT" for item in share_fks)

        command.downgrade(config, "0001_identity_sessions")
        downgraded_tables = set(inspect(connection).get_table_names())
        assert {"documents", "document_shares"}.isdisjoint(downgraded_tables)
        assert {"roles", "users", "auth_sessions"} <= downgraded_tables
        roles_after_downgrade = set(
            connection.execute(text("SELECT name FROM roles")).scalars()
        )
        assert roles_after_downgrade == {"user", "administrator"}

        command.upgrade(config, "head")
        assert {"documents", "document_shares"} <= set(
            inspect(connection).get_table_names()
        )

    engine.dispose()


def test_document_revision_metadata_and_models_are_registered() -> None:
    from importlib.util import module_from_spec, spec_from_file_location

    from app.db.base import Base
    from app.models import Document, DocumentShare

    assert "documents" in Base.metadata.tables
    assert "document_shares" in Base.metadata.tables
    assert Document.__tablename__ == "documents"
    assert DocumentShare.__tablename__ == "document_shares"

    revision_path = Path("backend/migrations/versions/0002_documents.py")
    spec = spec_from_file_location("documents_migration", revision_path)
    assert spec is not None and spec.loader is not None
    migration = module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.revision == "0002_documents"
    assert migration.down_revision == "0001_identity_sessions"
