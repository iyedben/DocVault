"""Tests for Phase B3 document workspace, upload, download, and deletion integration."""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import httpx
import pytest
from app.api.dependencies import get_db
from app.api.routes.documents import get_document_storage
from app.core.config import AuthSettings
from app.db.base import Base
from app.main import app
from app.models import Document, DocumentShare, Role, User
from app.security.passwords import hash_password
from app.security.sessions import issue_auth_session
from app.storage import PrivateDocumentStorage
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

VALID_PDF = (Path(__file__).parent / "fixtures" / "minimal_valid.pdf").read_bytes()
TEST_PASSWORD = "StrongPassword#2026-Test"


@pytest.fixture
def doc_env() -> Generator[tuple[httpx.AsyncClient, sessionmaker[Session], User, User, str, str, str, str, PrivateDocumentStorage], None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    temp_dir = TemporaryDirectory()
    storage_root = Path(temp_dir.name)
    storage = PrivateDocumentStorage(storage_root, max_size_bytes=10 * 1024 * 1024)

    settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)

    with session_factory() as db:
        user_role = Role(name="user")
        admin_role = Role(name="administrator")
        db.add_all([user_role, admin_role])
        db.flush()

        alice = User(
            username="alice",
            password_hash=hash_password(TEST_PASSWORD),
            role=user_role,
        )
        bob = User(
            username="bob",
            password_hash=hash_password(TEST_PASSWORD),
            role=user_role,
        )
        db.add_all([alice, bob])
        db.flush()

        _, alice_session_token, alice_csrf_token = issue_auth_session(db, alice, settings)
        _, bob_session_token, bob_csrf_token = issue_auth_session(db, bob, settings)
        db.commit()

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    def override_get_storage():
        yield storage

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_document_storage] = override_get_storage

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client, session_factory, alice, bob, alice_session_token, alice_csrf_token, bob_session_token, bob_csrf_token, storage

    gen = run()
    val = asyncio.run(anext(gen))
    try:
        yield val
    finally:
        try:
            asyncio.run(anext(gen))
        except StopAsyncIteration:
            pass
        app.dependency_overrides.clear()
        storage.close()
        temp_dir.cleanup()
        engine.dispose()


def test_anonymous_cannot_access_documents(doc_env) -> None:
    client, _, _, _, _, _, _, _, _ = doc_env

    # 1. Anonymous listing is rejected with 401
    resp = asyncio.run(client.get("/api/v1/documents"))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Authentication required"

    # 2. Anonymous upload is rejected with 401
    upload_resp = asyncio.run(client.post("/api/v1/documents"))
    assert upload_resp.status_code == 401


def test_authenticated_user_empty_document_list(doc_env) -> None:
    client, _, _, _, alice_session, _, _, _, _ = doc_env

    client.cookies.set("docvault_session", alice_session)
    resp = asyncio.run(client.get("/api/v1/documents"))
    assert resp.status_code == 200
    assert resp.json() == []


def test_authenticated_user_populated_document_list_with_access_types(doc_env) -> None:
    client, session_factory, alice, bob, alice_session, _, _, _, storage = doc_env

    # Create Alice's owned document
    key1 = uuid4()
    staged1 = storage.create_staged_file()
    storage.write_chunks(staged1, [VALID_PDF])
    storage.promote(staged1, key1)

    # Create Bob's document shared with Alice
    key2 = uuid4()
    staged2 = storage.create_staged_file()
    storage.write_chunks(staged2, [VALID_PDF])
    storage.promote(staged2, key2)

    with session_factory() as db:
        doc1 = Document(
            owner_id=alice.id,
            display_filename="alice_report.pdf",
            media_type="application/pdf",
            file_size=len(VALID_PDF),
            storage_key=key1,
            status="active",
        )
        doc2 = Document(
            owner_id=bob.id,
            display_filename="bob_shared.pdf",
            media_type="application/pdf",
            file_size=len(VALID_PDF),
            storage_key=key2,
            status="active",
        )
        db.add_all([doc1, doc2])
        db.flush()
        share = DocumentShare(document_id=doc2.id, recipient_user_id=alice.id)
        db.add(share)
        db.commit()

    client.cookies.set("docvault_session", alice_session)
    resp = asyncio.run(client.get("/api/v1/documents"))
    assert resp.status_code == 200
    docs = resp.json()
    assert len(docs) == 2

    # Check access distinction
    owned = next(d for d in docs if d["display_filename"] == "alice_report.pdf")
    shared = next(d for d in docs if d["display_filename"] == "bob_shared.pdf")

    assert owned["access"] == "owner"
    assert owned["media_type"] == "application/pdf"
    assert owned["file_size"] == len(VALID_PDF)

    assert shared["access"] == "shared"
    assert shared["media_type"] == "application/pdf"


def test_upload_validation_non_pdf_rejected(doc_env) -> None:
    client, _, _, _, alice_session, alice_csrf, _, _, _ = doc_env

    client.cookies.set("docvault_session", alice_session)
    files = {"file": ("malicious.txt", b"plain text is not a pdf", "text/plain")}
    resp = asyncio.run(
        client.post(
            "/api/v1/documents",
            headers={"X-CSRF-Token": alice_csrf},
            files=files,
        )
    )
    assert resp.status_code == 422
    assert "Only valid PDF documents are supported" in resp.json()["detail"]


def test_upload_validation_oversized_file_rejected(doc_env) -> None:
    client, _, _, _, alice_session, alice_csrf, _, _, _ = doc_env

    client.cookies.set("docvault_session", alice_session)
    # File larger than 10 MiB limit
    oversized_data = b"%PDF-1.4\n" + b"A" * (10 * 1024 * 1024 + 1024)
    files = {"file": ("huge.pdf", oversized_data, "application/pdf")}
    resp = asyncio.run(
        client.post(
            "/api/v1/documents",
            headers={"X-CSRF-Token": alice_csrf},
            files=files,
        )
    )
    assert resp.status_code == 413
    assert "exceeds the maximum permitted size" in resp.json()["detail"]


def test_upload_successful_with_csrf(doc_env) -> None:
    client, session_factory, alice, _, alice_session, alice_csrf, _, _, _ = doc_env

    client.cookies.set("docvault_session", alice_session)
    files = {"file": ("valid_contract.pdf", VALID_PDF, "application/pdf")}
    resp = asyncio.run(
        client.post(
            "/api/v1/documents",
            headers={"X-CSRF-Token": alice_csrf},
            files=files,
        )
    )
    assert resp.status_code == 201
    doc_data = resp.json()
    assert doc_data["display_filename"] == "valid_contract.pdf"
    assert doc_data["access"] == "owner"
    assert doc_data["file_size"] == len(VALID_PDF)
    assert doc_data["media_type"] == "application/pdf"

    # Confirm record created in PostgreSQL
    with session_factory() as db:
        created = db.scalar(select(Document).where(Document.display_filename == "valid_contract.pdf"))
        assert created is not None
        assert created.owner_id == alice.id
        assert created.status == "active"


def test_upload_missing_or_bad_csrf_rejected(doc_env) -> None:
    client, _, _, _, alice_session, _, _, _, _ = doc_env

    client.cookies.set("docvault_session", alice_session)
    files = {"file": ("valid.pdf", VALID_PDF, "application/pdf")}

    # Missing CSRF
    no_csrf = asyncio.run(client.post("/api/v1/documents", files=files))
    assert no_csrf.status_code == 403
    assert no_csrf.json()["detail"] == "CSRF validation failed"

    # Invalid CSRF
    bad_csrf = asyncio.run(
        client.post(
            "/api/v1/documents",
            headers={"X-CSRF-Token": "bad-csrf-token"},
            files=files,
        )
    )
    assert bad_csrf.status_code == 403
    assert bad_csrf.json()["detail"] == "CSRF validation failed"


def test_download_document_success(doc_env) -> None:
    client, session_factory, alice, _, alice_session, _, _, _, storage = doc_env

    key = uuid4()
    staged = storage.create_staged_file()
    storage.write_chunks(staged, [VALID_PDF])
    storage.promote(staged, key)

    with session_factory() as db:
        doc = Document(
            owner_id=alice.id,
            display_filename="download_me.pdf",
            media_type="application/pdf",
            file_size=len(VALID_PDF),
            storage_key=key,
            status="active",
        )
        db.add(doc)
        db.commit()
        doc_id = str(doc.id)

    client.cookies.set("docvault_session", alice_session)
    resp = asyncio.run(client.get(f"/api/v1/documents/{doc_id}/download"))
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers["content-disposition"]
    assert "download_me.pdf" in resp.headers["content-disposition"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.content == VALID_PDF


def test_download_document_unauthorized_returns_404(doc_env) -> None:
    client, session_factory, alice, _, _, _, bob_session, _, storage = doc_env

    # Alice owns document, NOT shared with Bob
    key = uuid4()
    staged = storage.create_staged_file()
    storage.write_chunks(staged, [VALID_PDF])
    storage.promote(staged, key)

    with session_factory() as db:
        doc = Document(
            owner_id=alice.id,
            display_filename="alice_private.pdf",
            media_type="application/pdf",
            file_size=len(VALID_PDF),
            storage_key=key,
            status="active",
        )
        db.add(doc)
        db.commit()
        doc_id = str(doc.id)

    # Bob attempts to download Alice's document -> 404
    client.cookies.set("docvault_session", bob_session)
    resp = asyncio.run(client.get(f"/api/v1/documents/{doc_id}/download"))
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Document not found"


def test_delete_document_success_by_owner(doc_env) -> None:
    client, session_factory, alice, _, alice_session, alice_csrf, _, _, storage = doc_env

    key = uuid4()
    staged = storage.create_staged_file()
    storage.write_chunks(staged, [VALID_PDF])
    storage.promote(staged, key)

    with session_factory() as db:
        doc = Document(
            owner_id=alice.id,
            display_filename="to_delete.pdf",
            media_type="application/pdf",
            file_size=len(VALID_PDF),
            storage_key=key,
            status="active",
        )
        db.add(doc)
        db.commit()
        doc_id = str(doc.id)

    client.cookies.set("docvault_session", alice_session)
    del_resp = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc_id}",
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert del_resp.status_code == 204

    # Document removed from listing
    list_resp = asyncio.run(client.get("/api/v1/documents"))
    assert list_resp.status_code == 200
    assert not any(d["id"] == doc_id for d in list_resp.json())


def test_delete_document_unauthorized_by_sharee_returns_404(doc_env) -> None:
    client, session_factory, alice, bob, _, _, bob_session, bob_csrf, storage = doc_env

    # Alice owns document, shared with Bob
    key = uuid4()
    staged = storage.create_staged_file()
    storage.write_chunks(staged, [VALID_PDF])
    storage.promote(staged, key)

    with session_factory() as db:
        doc = Document(
            owner_id=alice.id,
            display_filename="shared_with_bob.pdf",
            media_type="application/pdf",
            file_size=len(VALID_PDF),
            storage_key=key,
            status="active",
        )
        db.add(doc)
        db.flush()
        share = DocumentShare(document_id=doc.id, recipient_user_id=bob.id)
        db.add(share)
        db.commit()
        doc_id = str(doc.id)

    # Bob attempts to delete document he doesn't own -> 404
    client.cookies.set("docvault_session", bob_session)
    del_resp = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc_id}",
            headers={"X-CSRF-Token": bob_csrf},
        )
    )
    assert del_resp.status_code == 404
    assert del_resp.json()["detail"] == "Document not found"

    # Confirm document still exists for Alice
    with session_factory() as db:
        assert db.get(Document, doc.id) is not None


def test_delete_document_bad_csrf_returns_403(doc_env) -> None:
    client, session_factory, alice, _, alice_session, _, _, _, storage = doc_env

    key = uuid4()
    staged = storage.create_staged_file()
    storage.write_chunks(staged, [VALID_PDF])
    storage.promote(staged, key)

    with session_factory() as db:
        doc = Document(
            owner_id=alice.id,
            display_filename="protected.pdf",
            media_type="application/pdf",
            file_size=len(VALID_PDF),
            storage_key=key,
            status="active",
        )
        db.add(doc)
        db.commit()
        doc_id = str(doc.id)

    client.cookies.set("docvault_session", alice_session)
    del_resp = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc_id}",
            headers={"X-CSRF-Token": "invalid-csrf"},
        )
    )
    assert del_resp.status_code == 403
    assert del_resp.json()["detail"] == "CSRF validation failed"

    # Document still exists
    with session_factory() as db:
        assert db.get(Document, doc.id) is not None


def test_static_document_modules_served(doc_env) -> None:
    client, _, _, _, _, _, _, _, _ = doc_env

    doc_service_resp = asyncio.run(client.get("/static/js/documents.js"))
    assert doc_service_resp.status_code == 200
    assert "uploadDocument" in doc_service_resp.text
    assert "listDocuments" in doc_service_resp.text
    assert "downloadDocument" in doc_service_resp.text
    assert "deleteDocument" in doc_service_resp.text

    doc_view_resp = asyncio.run(client.get("/static/js/views/documents.js"))
    assert doc_view_resp.status_code == 200
    assert "renderDocumentsView" in doc_view_resp.text
    assert "Document Workspace" in doc_view_resp.text
