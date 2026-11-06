"""Focused document API integration tests against disposable PostgreSQL."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import threading
import uuid
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from app.api.routes.documents import get_document_storage
from app.core.config import AuthSettings
from app.db.session import get_db as production_get_db
from app.main import app
from app.models import Document, DocumentShare, Role, User
from app.models.user import utcnow
from app.security.sessions import issue_auth_session
from app.storage import (
    PrivateDocumentStorage,
    StorageError,
    StoredFileNotFound,
)
from sqlalchemy import Engine, create_engine, func, select, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

DATABASE_PREFIX = "dv_p4_document_"
OPERATION_TIMEOUT_SECONDS = 20
_ROOT = Path(__file__).resolve().parents[2]
_VALID_PDF = (
    Path(__file__).parent / "fixtures" / "minimal_valid.pdf"
).read_bytes()


@dataclass(frozen=True, slots=True)
class Identity:
    user_id: uuid.UUID
    session_token: str
    csrf_token: str


@dataclass(slots=True)
class DocumentHarness:
    engine: Engine
    sessions: sessionmaker[Session]
    storage: PrivateDocumentStorage

    def identity(self, role_name: str = "user") -> Identity:
        with self.sessions() as session:
            role = session.scalar(select(Role).where(Role.name == role_name))
            assert role is not None
            user = User(
                username=f"pg_{secrets.token_hex(10)}",
                password_hash=f"postgres-integration-{secrets.token_hex(16)}",
                role=role,
            )
            session.add(user)
            session.flush()
            _, session_token, csrf_token = issue_auth_session(
                session,
                user,
                AuthSettings(
                    cookie_secure=False,
                    session_ttl_seconds=3600,
                    idle_timeout_seconds=1800,
                ),
                now=utcnow(),
            )
            identity = Identity(user.id, session_token, csrf_token)
            session.commit()
            return identity

    def additional_session(self, identity: Identity) -> Identity:
        with self.sessions() as session:
            user = session.get(User, identity.user_id)
            assert user is not None
            _, session_token, csrf_token = issue_auth_session(
                session,
                user,
                AuthSettings(
                    cookie_secure=False,
                    session_ttl_seconds=3600,
                    idle_timeout_seconds=1800,
                ),
                now=utcnow(),
            )
            session.commit()
        return Identity(identity.user_id, session_token, csrf_token)

    def create_document(
        self,
        owner: Identity,
        *,
        shared_with: Identity | None = None,
        status: str = "active",
    ) -> Document:
        storage_key = uuid.uuid4()
        staged = self.storage.create_staged_file()
        self.storage.write_chunks(staged, [_VALID_PDF])
        self.storage.promote(staged, storage_key)
        with self.sessions() as session:
            document = Document(
                owner_id=owner.user_id,
                display_filename="pg-integration.pdf",
                media_type="application/pdf",
                file_size=len(_VALID_PDF),
                storage_key=storage_key,
                status=status,  # type: ignore[arg-type]
            )
            session.add(document)
            session.flush()
            if shared_with is not None:
                session.add(
                    DocumentShare(
                        document_id=document.id,
                        recipient_user_id=shared_with.user_id,
                    )
                )
            session.commit()
            session.refresh(document)
            return document

    async def async_request(
        self,
        method: str,
        path: str,
        identity: Identity | None = None,
    ) -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://docvault-postgres.test",
        ) as client:
            if identity is not None:
                client.cookies.set("docvault_session", identity.session_token)
                client.headers["X-CSRF-Token"] = identity.csrf_token
            return await client.request(method, path)

    def request(
        self,
        method: str,
        path: str,
        identity: Identity | None = None,
    ) -> httpx.Response:
        return asyncio.run(self.async_request(method, path, identity))


def _test_database_settings() -> tuple[str, int, str, str]:
    host = os.environ.get("PHASE4_TEST_PG_HOST", "")
    port_value = os.environ.get("PHASE4_TEST_PG_PORT", "")
    username = os.environ.get("PHASE4_TEST_PG_USER", "")
    password = os.environ.get("PHASE4_TEST_PG_PASSWORD", "")
    if host != "127.0.0.1" or not port_value.isdigit() or not username or not password:
        pytest.skip("Use scripts/run_phase4_pg_document_tests.sh for isolated PostgreSQL")
    port = int(port_value)
    if not 1 <= port <= 65535:
        pytest.fail("Isolated PostgreSQL test port is invalid")
    if re.fullmatch(r"dv4test_[0-9a-f]{12}", username) is None:
        pytest.fail("Unexpected PostgreSQL user for isolated integration test")
    return host, port, username, password


def _new_engine(
    host: str,
    port: int,
    username: str,
    password: str,
    database: str,
) -> Engine:
    url = URL.create(
        "postgresql+psycopg",
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
    )
    return create_engine(
        url,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": 5,
            "options": "-c lock_timeout=15000 -c statement_timeout=30000",
        },
    )


def _apply_existing_migrations(engine: Engine) -> None:
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(_ROOT / "backend" / "migrations"))
    config.set_main_option("prepend_sys_path", str(_ROOT / "backend"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


@pytest.fixture(scope="session")
def isolated_postgres_engine() -> Generator[Engine, None, None]:
    host, port, username, password = _test_database_settings()
    database_name = f"{DATABASE_PREFIX}{uuid.uuid4().hex}"
    if re.fullmatch(r"dv_p4_document_[0-9a-f]{32}", database_name) is None:
        pytest.fail("Generated isolated database name failed its safety check")

    admin_engine = _new_engine(host, port, username, password, "postgres")
    database_created = False
    test_engine: Engine | None = None
    try:
        with admin_engine.connect() as connection:
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            identity = connection.execute(
                text("SELECT current_user, current_database()")
            ).one()
            if identity != (username, "postgres"):
                pytest.fail("Connection is not to the expected disposable PostgreSQL")
            version = connection.execute(text("SHOW server_version_num")).scalar_one()
            if int(version) // 10000 != 17:
                pytest.fail("Disposable PostgreSQL must be major version 17")
            isolation = connection.execute(text("SHOW transaction_isolation")).scalar_one()
            if isolation.lower() != "read committed":
                pytest.fail("Disposable PostgreSQL must use READ COMMITTED isolation")
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
            database_created = True

        test_engine = _new_engine(host, port, username, password, database_name)
        _apply_existing_migrations(test_engine)
        yield test_engine
    finally:
        if test_engine is not None:
            test_engine.dispose()
        try:
            if database_created:
                with admin_engine.connect() as connection:
                    connection = connection.execution_options(isolation_level="AUTOCOMMIT")
                    connection.execute(
                        text(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname = :database_name AND pid <> pg_backend_pid()"
                        ),
                        {"database_name": database_name},
                    )
                    connection.exec_driver_sql(
                        f'DROP DATABASE IF EXISTS "{database_name}"'
                    )
        finally:
            admin_engine.dispose()


@pytest.fixture
def postgres_harness(
    isolated_postgres_engine: Engine,
    tmp_path: Path,
) -> Generator[DocumentHarness, None, None]:
    engine = isolated_postgres_engine
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    storage = PrivateDocumentStorage(tmp_path / "private-documents")

    def db_dependency() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    def storage_dependency() -> Generator[PrivateDocumentStorage, None, None]:
        yield storage

    app.dependency_overrides[production_get_db] = db_dependency
    app.dependency_overrides[get_document_storage] = storage_dependency
    harness = DocumentHarness(engine, sessions, storage)
    try:
        yield harness
    finally:
        app.dependency_overrides.clear()
        storage.close()


def test_postgres_concurrent_duplicate_grants_are_deterministic_and_unique(
    postgres_harness: DocumentHarness,
) -> None:
    harness = postgres_harness
    owner = harness.identity()
    owner_second_session = harness.additional_session(owner)
    recipient = harness.identity()
    api_document = harness.create_document(owner)
    start = threading.Barrier(3)

    def grant(identity: Identity) -> int:
        start.wait(timeout=5)
        return asyncio.run(
            harness.async_request(
                "PUT",
                f"/api/v1/documents/{api_document.id}/shares/{recipient.user_id}",
                identity,
            )
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(grant, owner),
            executor.submit(grant, owner_second_session),
        ]
        start.wait(timeout=5)
        api_results = [future.result(timeout=OPERATION_TIMEOUT_SECONDS) for future in futures]
    assert sorted(api_results) == [201, 409]
    with harness.sessions() as session:
        api_share_count = session.scalar(
            select(func.count()).select_from(DocumentShare).where(
                DocumentShare.document_id == api_document.id,
                DocumentShare.recipient_user_id == recipient.user_id,
            )
        )
    assert api_share_count == 1

    constraint_document = harness.create_document(owner)
    insert_start = threading.Barrier(2)

    def direct_concurrent_insert() -> str:
        with harness.sessions() as session:
            session.add(
                DocumentShare(
                    document_id=constraint_document.id,
                    recipient_user_id=recipient.user_id,
                )
            )
            insert_start.wait(timeout=5)
            try:
                session.commit()
                return "inserted"
            except IntegrityError:
                session.rollback()
                return "unique-conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        unique_results = list(
            executor.map(lambda _index: direct_concurrent_insert(), range(2))
        )
    assert sorted(unique_results) == ["inserted", "unique-conflict"]
    with harness.sessions() as session:
        direct_share_count = session.scalar(
            select(func.count()).select_from(DocumentShare).where(
                DocumentShare.document_id == constraint_document.id,
                DocumentShare.recipient_user_id == recipient.user_id,
            )
        )
    assert direct_share_count == 1


def test_postgres_delete_commits_tombstone_before_unlink_and_blocks_concurrent_access(
    postgres_harness: DocumentHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = postgres_harness
    owner = harness.identity()
    recipient = harness.identity()
    other_user = harness.identity()
    document = harness.create_document(owner, shared_with=recipient)
    original_delete = harness.storage.delete_file
    unlink_entered = threading.Event()
    allow_unlink = threading.Event()

    def observe_then_block(storage_key: uuid.UUID) -> bool:
        with harness.sessions() as observer:
            persisted = observer.get(Document, document.id)
            assert persisted is not None and persisted.status == "deleting"
        with harness.storage.open_file(storage_key) as stored:
            assert stored.read() == _VALID_PDF
        unlink_entered.set()
        if not allow_unlink.wait(timeout=OPERATION_TIMEOUT_SECONDS):
            raise TimeoutError("Timed out waiting to continue PostgreSQL deletion")
        return original_delete(storage_key)

    monkeypatch.setattr(harness.storage, "delete_file", observe_then_block)

    with ThreadPoolExecutor(max_workers=1) as executor:
        delete_future = executor.submit(
            lambda: asyncio.run(
                harness.async_request(
                    "DELETE", f"/api/v1/documents/{document.id}", owner
                )
            )
        )
        assert unlink_entered.wait(timeout=OPERATION_TIMEOUT_SECONDS)
        try:
            with harness.sessions() as observer:
                persisted = observer.get(Document, document.id)
                assert persisted is not None and persisted.status == "deleting"
            download = harness.request(
                "GET", f"/api/v1/documents/{document.id}/download", recipient
            )
            share = harness.request(
                "PUT",
                f"/api/v1/documents/{document.id}/shares/{other_user.user_id}",
                owner,
            )
            assert download.status_code == 404
            assert share.status_code == 404
        finally:
            allow_unlink.set()
        assert delete_future.result(timeout=OPERATION_TIMEOUT_SECONDS).status_code == 204


def test_postgres_multi_user_access_and_revocation_are_isolated(
    postgres_harness: DocumentHarness,
) -> None:
    harness = postgres_harness
    owner = harness.identity()
    recipient = harness.identity()
    outsider = harness.identity()
    admin = harness.identity("administrator")
    target = harness.identity()
    document = harness.create_document(owner, shared_with=recipient)

    for authorized in (owner, recipient):
        assert harness.request(
            "GET", f"/api/v1/documents/{document.id}", authorized
        ).status_code == 200
        assert harness.request(
            "GET", f"/api/v1/documents/{document.id}/download", authorized
        ).status_code == 200

    for denied in (outsider, admin):
        assert harness.request(
            "GET", f"/api/v1/documents/{document.id}", denied
        ).status_code == 404
        assert harness.request(
            "GET", f"/api/v1/documents/{document.id}/download", denied
        ).status_code == 404
        assert harness.request(
            "DELETE", f"/api/v1/documents/{document.id}", denied
        ).status_code == 404
        assert harness.request(
            "GET", f"/api/v1/documents/{document.id}/shares", denied
        ).status_code == 404
        assert harness.request(
            "PUT",
            f"/api/v1/documents/{document.id}/shares/{target.user_id}",
            denied,
        ).status_code == 404
        assert harness.request(
            "DELETE",
            f"/api/v1/documents/{document.id}/shares/{recipient.user_id}",
            denied,
        ).status_code == 404

    assert harness.request(
        "DELETE",
        f"/api/v1/documents/{document.id}/shares/{recipient.user_id}",
        owner,
    ).status_code == 204
    for path in (
        f"/api/v1/documents/{document.id}",
        f"/api/v1/documents/{document.id}/download",
    ):
        assert harness.request("GET", path, recipient).status_code == 404
        assert harness.request("GET", path, outsider).status_code == 404
        assert harness.request("GET", path, admin).status_code == 404
        assert harness.request("GET", path, owner).status_code == 200


def test_postgres_filesystem_failure_keeps_committed_inaccessible_tombstone(
    postgres_harness: DocumentHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = postgres_harness
    owner = harness.identity()
    recipient = harness.identity()
    document = harness.create_document(owner, shared_with=recipient)

    def fail_unlink(_storage_key: uuid.UUID) -> bool:
        raise StorageError("synthetic PostgreSQL test failure")

    monkeypatch.setattr(harness.storage, "delete_file", fail_unlink)
    response = harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", owner
    )
    assert response.status_code == 500
    with harness.sessions() as observer:
        persisted = observer.get(Document, document.id)
        assert persisted is not None and persisted.status == "deleting"
    for identity in (owner, recipient):
        assert harness.request(
            "GET", f"/api/v1/documents/{document.id}", identity
        ).status_code == 404
        assert harness.request(
            "GET", f"/api/v1/documents/{document.id}/download", identity
        ).status_code == 404


def test_postgres_final_database_cleanup_failure_keeps_tombstone_after_unlink(
    postgres_harness: DocumentHarness,
) -> None:
    harness = postgres_harness
    owner = harness.identity()
    document = harness.create_document(owner)
    suffix = secrets.token_hex(5)
    function_name = f"test_fail_doc_cleanup_{suffix}"
    trigger_name = f"test_fail_doc_cleanup_trigger_{suffix}"
    with harness.engine.begin() as connection:
        connection.exec_driver_sql(
            f"CREATE FUNCTION {function_name}() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN "
            "RAISE EXCEPTION 'synthetic deferred cleanup failure'; "
            "END; $$"
        )
        connection.exec_driver_sql(
            f"CREATE CONSTRAINT TRIGGER {trigger_name} "
            f"AFTER DELETE ON documents DEFERRABLE INITIALLY DEFERRED "
            f"FOR EACH ROW EXECUTE FUNCTION {function_name}()"
        )

    try:
        response = harness.request(
            "DELETE", f"/api/v1/documents/{document.id}", owner
        )
        assert response.status_code == 500
        with harness.sessions() as observer:
            persisted = observer.get(Document, document.id)
            assert persisted is not None and persisted.status == "deleting"
        with pytest.raises(StoredFileNotFound):
            harness.storage.open_file(document.storage_key)
        assert harness.request(
            "GET", f"/api/v1/documents/{document.id}", owner
        ).status_code == 404
    finally:
        with harness.engine.begin() as connection:
            connection.exec_driver_sql(
                f"DROP TRIGGER IF EXISTS {trigger_name} ON documents"
            )
            connection.exec_driver_sql(f"DROP FUNCTION IF EXISTS {function_name}()")

    retry = harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", owner
    )
    assert retry.status_code == 204
    with harness.sessions() as observer:
        assert observer.get(Document, document.id) is None
