"""Document API tests use isolated SQLite databases and temporary storage."""

import asyncio
import hmac
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

import httpx
import pytest
from app.api.dependencies import get_current_auth, require_csrf
from app.api.routes.documents import get_document_storage
from app.audit import logger as security_logger
from app.core.config import (
    DOCUMENT_MULTIPART_OVERHEAD_BYTES,
    AuthSettings,
)
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.middleware.document_limits import DocumentRequestLimitsMiddleware
from app.models import AuthSession, Document, DocumentShare, Role, User
from app.models.user import utcnow
from app.security.sessions import AuthContext, issue_auth_session
from app.security.tokens import hash_token
from app.storage import PrivateDocumentStorage, StorageError, StoredFileNotFound
from fastapi import Depends, HTTPException, Request
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.types import Message, Receive, Scope, Send

VALID_PDF = (Path(__file__).parent / "fixtures" / "minimal_valid.pdf").read_bytes()


@dataclass(frozen=True, slots=True)
class UserIdentity:
    user: User
    session_token: str
    csrf_token: str


@dataclass(slots=True)
class APIHarness:
    db: Session
    sessions: sessionmaker[Session]
    storage: PrivateDocumentStorage
    storage_root: Path
    identities: dict[str, UserIdentity]

    def identity(self, username: str, role_name: str = "user") -> UserIdentity:
        role = self.db.scalar(select(Role).where(Role.name == role_name))
        assert role is not None
        user = User(username=username, password_hash="synthetic-test-hash", role=role)
        self.db.add(user)
        self.db.flush()
        auth_session, session_token, csrf_token = issue_auth_session(
            self.db,
            user,
            AuthSettings(
                cookie_secure=False,
                session_ttl_seconds=3600,
                idle_timeout_seconds=1800,
            ),
            now=utcnow(),
        )
        self.db.commit()
        self.db.expunge(user)
        self.db.expunge(auth_session)
        identity = UserIdentity(user, session_token, csrf_token)
        self.identities[session_token] = identity
        return identity

    def create_document(
        self,
        owner: UserIdentity,
        *,
        status: str = "active",
        shared_with: UserIdentity | None = None,
    ) -> Document:
        storage_key = uuid4()
        staged = self.storage.create_staged_file()
        self.storage.write_chunks(staged, [VALID_PDF[:5], VALID_PDF[5:]])
        self.storage.promote(staged, storage_key)
        document = Document(
            owner_id=owner.user.id,
            display_filename="report.pdf",
            media_type="application/pdf",
            file_size=len(VALID_PDF),
            storage_key=storage_key,
            status=status,  # type: ignore[arg-type]
        )
        self.db.add(document)
        self.db.flush()
        if shared_with is not None:
            self.db.add(
                DocumentShare(
                    document_id=document.id,
                    recipient_user_id=shared_with.user.id,
                )
            )
        self.db.commit()
        return document

    def request(
        self,
        method: str,
        path: str,
        *,
        identity: UserIdentity | None = None,
        csrf: bool = True,
        **kwargs: object,
    ) -> httpx.Response:
        return asyncio.run(
            self.async_request(method, path, identity=identity, csrf=csrf, **kwargs)
        )

    async def async_request(
        self,
        method: str,
        path: str,
        *,
        identity: UserIdentity | None = None,
        csrf: bool = True,
        **kwargs: object,
    ) -> httpx.Response:
        async def send_request() -> httpx.Response:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://docvault.test",
            ) as client:
                if identity is not None:
                    client.cookies.set("docvault_session", identity.session_token)
                    if csrf:
                        client.headers["X-CSRF-Token"] = identity.csrf_token
                return await client.request(method, path, **kwargs)

        return await send_request()


@pytest.fixture
def api_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[APIHarness]:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'documents.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db = sessions()
    db.add_all([Role(name="user"), Role(name="administrator")])
    db.commit()
    storage_root = tmp_path / "document-volume"
    monkeypatch.setenv("DOCUMENT_STORAGE_ROOT", str(storage_root))
    monkeypatch.setenv("DOCUMENT_MAX_SIZE_BYTES", "10485760")
    monkeypatch.setenv(
        "DOCUMENT_MAX_REQUEST_BODY_BYTES",
        str(10 * 1024 * 1024 + DOCUMENT_MULTIPART_OVERHEAD_BYTES),
    )
    storage = PrivateDocumentStorage(storage_root, max_size_bytes=10 * 1024 * 1024)
    harness = APIHarness(db, sessions, storage, storage_root, {})

    async def db_dependency() -> AsyncIterator[Session]:
        with sessions() as session:
            yield session

    async def override_storage() -> PrivateDocumentStorage:
        return storage

    async def override_auth(request: Request) -> AuthContext:
        token = request.cookies.get("docvault_session")
        identity = harness.identities.get(token or "")
        if identity is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        with sessions() as session:
            auth_session = session.scalar(
                select(AuthSession).where(
                    AuthSession.session_token_hash == hash_token(identity.session_token)
                )
            )
            assert auth_session is not None
            session.expunge(auth_session)
        return AuthContext(user=identity.user, auth_session=auth_session)

    async def csrf_dependency(
        request: Request,
        auth: Annotated[AuthContext, Depends(override_auth)],
    ) -> AuthContext:
        csrf_token = request.headers.get("X-CSRF-Token", "")
        if not csrf_token or not hmac.compare_digest(
            auth.auth_session.csrf_token_hash,
            hash_token(csrf_token),
        ):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        return auth

    app.dependency_overrides[get_db] = db_dependency
    app.dependency_overrides[get_document_storage] = override_storage
    app.dependency_overrides[get_current_auth] = override_auth
    app.dependency_overrides[require_csrf] = csrf_dependency
    try:
        yield harness
    finally:
        app.dependency_overrides.clear()
        storage.close()
        db.close()
        engine.dispose()


def upload(
    harness: APIHarness,
    identity: UserIdentity | None,
    *,
    filename: str = "report.pdf",
    content: bytes = VALID_PDF,
    media_type: str = "application/pdf",
    csrf: bool = True,
) -> httpx.Response:
    return harness.request(
        "POST",
        "/api/v1/documents",
        identity=identity,
        csrf=csrf,
        files={"file": (filename, content, media_type)},
    )


def assert_private(response: httpx.Response) -> None:
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize(
    ("filename", "content", "media_type"),
    [
        ("report.txt", VALID_PDF, "application/pdf"),
        ("report.pdf", VALID_PDF, "image/pdf"),
        ("report.pdf", b"invalid", "application/pdf"),
        ("report.pdf", b"", "application/pdf"),
        ("../escape.pdf", VALID_PDF, "application/pdf"),
        ("folder\\escape.pdf", VALID_PDF, "application/pdf"),
    ],
)
def test_upload_rejects_invalid_pdf_or_filename(
    api_harness: APIHarness,
    filename: str,
    content: bytes,
    media_type: str,
) -> None:
    owner = api_harness.identity("invalidupload")
    response = upload(
        api_harness,
        owner,
        filename=filename,
        content=content,
        media_type=media_type,
    )
    assert response.status_code == 422
    assert_private(response)
    assert api_harness.db.scalars(select(Document)).all() == []
    assert list(api_harness.storage_root.iterdir()) == []


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-1.4\nnot a document\n%%EOF\n",
        VALID_PDF[:-24],
    ],
    ids=["invalid-structure", "truncated"],
)
def test_upload_rejects_structurally_invalid_pdf_and_cleans_staging(
    api_harness: APIHarness,
    content: bytes,
) -> None:
    owner = api_harness.identity("malformedupload")
    response = upload(api_harness, owner, content=content)
    assert response.status_code == 422
    assert_private(response)
    assert api_harness.db.scalars(select(Document)).all() == []
    assert list(api_harness.storage_root.iterdir()) == []


def test_upload_accepts_structural_pdf_with_javascript_without_claiming_safety(
    api_harness: APIHarness,
) -> None:
    suspicious_pdf = (
        Path(__file__).parent / "fixtures" / "valid_with_embedded_javascript.pdf"
    ).read_bytes()
    owner = api_harness.identity("suspiciousbutvalid")
    response = upload(api_harness, owner, content=suspicious_pdf)
    assert response.status_code == 201
    assert_private(response)
    document = api_harness.db.get(Document, UUID(response.json()["id"]))
    assert document is not None
    with api_harness.storage.open_file(document.storage_key) as stored:
        assert stored.read() == suspicious_pdf


def test_valid_upload_uses_session_owner_and_opaque_storage_key(
    api_harness: APIHarness,
) -> None:
    owner = api_harness.identity("uploadowner")
    response = upload(api_harness, owner, filename="résumé.pdf")
    assert response.status_code == 201
    assert_private(response)
    payload = response.json()
    assert payload["display_filename"] == "résumé.pdf"
    assert payload["file_size"] == len(VALID_PDF)
    assert "storage_key" not in payload and "owner_id" not in payload
    document = api_harness.db.get(Document, UUID(payload["id"]))
    assert document is not None and document.owner_id == owner.user.id
    with api_harness.storage.open_file(document.storage_key) as stored:
        assert stored.read() == VALID_PDF


def test_upload_requires_authentication_and_csrf(api_harness: APIHarness) -> None:
    owner = api_harness.identity("uploadcsrf")
    response = upload(api_harness, owner, csrf=False)
    assert response.status_code == 403
    assert_private(response)
    assert api_harness.db.scalars(select(Document)).all() == []


def test_upload_read_failure_removes_stage_and_preserves_existing_documents(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = api_harness.identity("uploadreadfailureowner")
    existing_document = api_harness.create_document(owner)

    async def fail_upload_read(
        _upload: StarletteUploadFile,
        _size: int = -1,
    ) -> bytes:
        raise OSError("synthetic multipart spool read failure")

    monkeypatch.setattr(StarletteUploadFile, "read", fail_upload_read)
    response = upload(api_harness, owner)

    assert response.status_code == 500
    assert response.json() == {"detail": "Document could not be read"}
    assert list(api_harness.db.scalars(select(Document)).all()) == [existing_document]
    with api_harness.storage.open_file(existing_document.storage_key) as stored:
        assert stored.read() == VALID_PDF
    assert {
        entry.name for entry in api_harness.storage_root.iterdir()
    } == {str(existing_document.storage_key)}


def test_upload_read_failure_is_not_masked_by_staging_cleanup_error(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = api_harness.identity("uploadcleanupfailureowner")
    original_cleanup = api_harness.storage.delete_staged_file

    async def fail_upload_read(
        _upload: StarletteUploadFile,
        _size: int = -1,
    ) -> bytes:
        raise OSError("synthetic original upload read failure")

    def cleanup_then_raise(staged) -> None:
        original_cleanup(staged)
        raise StorageError("synthetic secondary cleanup failure")

    monkeypatch.setattr(StarletteUploadFile, "read", fail_upload_read)
    monkeypatch.setattr(api_harness.storage, "delete_staged_file", cleanup_then_raise)
    response = upload(api_harness, owner)

    assert response.status_code == 500
    assert response.json() == {"detail": "Document could not be read"}
    assert api_harness.db.scalars(select(Document)).all() == []
    assert list(api_harness.storage_root.iterdir()) == []


def test_upload_rejects_unauthenticated_user(api_harness: APIHarness) -> None:
    response = upload(api_harness, None)
    assert response.status_code == 401
    assert_private(response)


def test_file_size_limit_rejects_oversized_upload(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCUMENT_MAX_SIZE_BYTES", "16")
    monkeypatch.setenv(
        "DOCUMENT_MAX_REQUEST_BODY_BYTES",
        str(16 + DOCUMENT_MULTIPART_OVERHEAD_BYTES),
    )
    owner = api_harness.identity("sizedupload")
    response = upload(api_harness, owner, content=b"%PDF-" + b"x" * 12)
    assert response.status_code == 413
    assert_private(response)
    assert api_harness.db.scalars(select(Document)).all() == []


def test_streamed_request_body_limit_is_enforced(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCUMENT_MAX_SIZE_BYTES", "32")
    monkeypatch.setenv(
        "DOCUMENT_MAX_REQUEST_BODY_BYTES",
        str(32 + DOCUMENT_MULTIPART_OVERHEAD_BYTES),
    )
    messages: list[Message] = [
        {"type": "http.request", "body": b"x" * 32_768, "more_body": True},
        {"type": "http.request", "body": b"x" * 32_768, "more_body": True},
        {"type": "http.request", "body": b"x" * 128, "more_body": False},
    ]
    sent: list[Message] = []

    async def receive() -> Message:
        return messages.pop(0)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        while (await receive())["more_body"]:
            pass

    async def send_message(message: Message) -> None:
        sent.append(message)

    async def invoke() -> None:
        await DocumentRequestLimitsMiddleware(app)(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/documents",
                "headers": [],
                "state": {},
            },
            receive,
            send_message,
        )

    asyncio.run(invoke())
    assert sent[0]["status"] == 413


@pytest.mark.parametrize("access", ["owner", "shared", "outsider", "admin"])
@pytest.mark.anyio
async def test_list_is_scoped_to_ownership_and_explicit_shares(
    api_harness: APIHarness,
    access: str,
) -> None:
    owner = api_harness.identity("listowner")
    recipient = api_harness.identity("listrecipient")
    outsider = api_harness.identity("listoutsider")
    admin = api_harness.identity("listadmin", "administrator")
    shared = recipient if access == "shared" else None
    document = api_harness.create_document(owner, shared_with=shared)
    identity = {
        "owner": owner,
        "shared": recipient,
        "outsider": outsider,
        "admin": admin,
    }[access]
    response = await api_harness.async_request(
        "GET", "/api/v1/documents", identity=identity
    )
    assert response.status_code == 200
    assert_private(response)
    assert len(response.json()) == (1 if access in {"owner", "shared"} else 0)
    if response.json():
        assert UUID(response.json()[0]["id"]) == document.id


def test_document_listing_requires_authentication(api_harness: APIHarness) -> None:
    response = api_harness.request("GET", "/api/v1/documents")
    assert response.status_code == 401
    assert_private(response)


@pytest.mark.parametrize("access", ["owner", "shared", "outsider", "admin", "deleting"])
def test_metadata_visibility_uses_active_owner_or_share_grants(
    api_harness: APIHarness,
    access: str,
) -> None:
    owner = api_harness.identity("metaowner")
    recipient = api_harness.identity("metarecipient")
    outsider = api_harness.identity("metaoutsider")
    admin = api_harness.identity("metaadmin", "administrator")
    status = "deleting" if access == "deleting" else "active"
    document = api_harness.create_document(
        owner,
        status=status,
        shared_with=recipient if access == "shared" else None,
    )
    identity = {
        "owner": owner,
        "shared": recipient,
        "outsider": outsider,
        "admin": admin,
        "deleting": owner,
    }[access]
    response = api_harness.request(
        "GET", f"/api/v1/documents/{document.id}", identity=identity
    )
    allowed = access in {"owner", "shared"}
    assert response.status_code == (200 if allowed else 404)
    assert_private(response)


@pytest.mark.parametrize("access", ["owner", "shared"])
def test_download_streams_pdf_with_private_attachment_headers(
    api_harness: APIHarness,
    access: str,
) -> None:
    owner = api_harness.identity("downloadowner")
    recipient = api_harness.identity("downloadrecipient")
    document = api_harness.create_document(
        owner, shared_with=recipient if access == "shared" else None
    )
    identity = owner if access == "owner" else recipient
    response = api_harness.request(
        "GET", f"/api/v1/documents/{document.id}/download", identity=identity
    )
    assert response.status_code == 200
    assert response.content == VALID_PDF
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"].startswith("attachment;")
    assert_private(response)


@pytest.mark.parametrize("access", ["outsider", "admin", "missing"])
def test_download_hides_inaccessible_documents(
    api_harness: APIHarness,
    access: str,
) -> None:
    owner = api_harness.identity("downloadprivateowner")
    outsider = api_harness.identity("downloadoutsider")
    admin = api_harness.identity("downloadadmin", "administrator")
    document = api_harness.create_document(owner)
    identity = {"outsider": outsider, "admin": admin, "missing": outsider}[access]
    target_id = uuid4() if access == "missing" else document.id
    response = api_harness.request(
        "GET", f"/api/v1/documents/{target_id}/download", identity=identity
    )
    assert response.status_code == 404
    assert_private(response)


def test_download_of_missing_stored_file_fails_closed(api_harness: APIHarness) -> None:
    owner = api_harness.identity("missingfileowner")
    document = api_harness.create_document(owner)
    api_harness.storage.delete_file(document.storage_key)
    response = api_harness.request(
        "GET", f"/api/v1/documents/{document.id}/download", identity=owner
    )
    assert response.status_code == 404
    assert_private(response)


def test_owner_delete_commits_tombstone_before_removing_file(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = api_harness.identity("deleteowner")
    document = api_harness.create_document(owner)
    observed: list[str] = []
    original_delete = api_harness.storage.delete_file

    def inspect_delete(storage_key: UUID) -> None:
        with api_harness.sessions() as session:
            persisted = session.get(Document, document.id)
            assert persisted is not None
            observed.append(persisted.status)
        # A separate transaction sees the committed tombstone while the file
        # still exists; the real unlink only happens after this callback.
        with api_harness.storage.open_file(storage_key) as stored:
            assert stored.read() == VALID_PDF
        original_delete(storage_key)

    monkeypatch.setattr(api_harness.storage, "delete_file", inspect_delete)
    response = api_harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", identity=owner
    )
    assert response.status_code == 204
    assert observed == ["deleting"]


@pytest.mark.parametrize("access", ["recipient", "outsider", "admin"])
def test_only_owner_can_delete_documents(
    api_harness: APIHarness,
    access: str,
) -> None:
    owner = api_harness.identity("deleteprivateowner")
    recipient = api_harness.identity("deleterecipient")
    outsider = api_harness.identity("deleteoutsider")
    admin = api_harness.identity("deleteadmin", "administrator")
    document = api_harness.create_document(
        owner, shared_with=recipient if access == "recipient" else None
    )
    identity = {"recipient": recipient, "outsider": outsider, "admin": admin}[access]
    response = api_harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", identity=identity
    )
    assert response.status_code == 404
    with api_harness.sessions() as session:
        persisted = session.get(Document, document.id)
        assert persisted is not None and persisted.status == "active"
    with api_harness.storage.open_file(document.storage_key) as stored:
        assert stored.read() == VALID_PDF


def test_delete_requires_csrf(api_harness: APIHarness) -> None:
    owner = api_harness.identity("csrfdeleteowner")
    document = api_harness.create_document(owner)
    response = api_harness.request(
        "DELETE",
        f"/api/v1/documents/{document.id}",
        identity=owner,
        csrf=False,
    )
    assert response.status_code == 403
    with api_harness.sessions() as session:
        persisted = session.get(Document, document.id)
        assert persisted is not None and persisted.status == "active"


def test_share_grant_requires_csrf(api_harness: APIHarness) -> None:
    owner = api_harness.identity("csrfshareowner")
    recipient = api_harness.identity("csrfsharerecipient")
    document = api_harness.create_document(owner)
    response = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
        csrf=False,
    )
    assert response.status_code == 403
    with api_harness.sessions() as session:
        assert session.scalar(select(DocumentShare).where(
            DocumentShare.document_id == document.id,
            DocumentShare.recipient_user_id == recipient.user.id,
        )) is None


def test_delete_with_missing_file_completes_safely_and_repeatably(
    api_harness: APIHarness,
) -> None:
    owner = api_harness.identity("deleteorphanowner")
    document = api_harness.create_document(owner)
    api_harness.storage.delete_file(document.storage_key)
    response = api_harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", identity=owner
    )
    assert response.status_code == 204
    retry = api_harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", identity=owner
    )
    assert retry.status_code == 404
    with api_harness.sessions() as session:
        assert session.get(Document, document.id) is None


def test_deletion_filesystem_failure_preserves_tombstone_for_retry(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = api_harness.identity("deletefailureowner")
    recipient = api_harness.identity("deletefailurerecipient")
    document = api_harness.create_document(owner, shared_with=recipient)
    original_delete = api_harness.storage.delete_file

    def fail_delete(storage_key: UUID) -> None:
        raise StorageError("synthetic storage failure")

    monkeypatch.setattr(api_harness.storage, "delete_file", fail_delete)
    response = api_harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", identity=owner
    )
    assert response.status_code == 500
    with api_harness.sessions() as session:
        persisted = session.get(Document, document.id)
        assert persisted is not None and persisted.status == "deleting"

    for identity in (owner, recipient):
        assert api_harness.request(
            "GET", f"/api/v1/documents/{document.id}", identity=identity
        ).status_code == 404
        assert api_harness.request(
            "GET", f"/api/v1/documents/{document.id}/download", identity=identity
        ).status_code == 404
        assert api_harness.request(
            "GET", "/api/v1/documents", identity=identity
        ).json() == []

    monkeypatch.setattr(api_harness.storage, "delete_file", original_delete)
    retry = api_harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", identity=owner
    )
    assert retry.status_code == 204
    with api_harness.sessions() as session:
        assert session.get(Document, document.id) is None
    assert list(api_harness.storage_root.iterdir()) == []


def test_deleting_document_cannot_be_listed_downloaded_or_shared(
    api_harness: APIHarness,
) -> None:
    owner = api_harness.identity("deletingstateowner")
    recipient = api_harness.identity("deletingstaterecipient")
    other_user = api_harness.identity("deletingstateother")
    document = api_harness.create_document(
        owner, status="deleting", shared_with=recipient
    )

    for identity in (owner, recipient):
        assert api_harness.request(
            "GET", "/api/v1/documents", identity=identity
        ).json() == []
        assert api_harness.request(
            "GET", f"/api/v1/documents/{document.id}", identity=identity
        ).status_code == 404
        assert api_harness.request(
            "GET", f"/api/v1/documents/{document.id}/download", identity=identity
        ).status_code == 404

    assert api_harness.request(
        "GET", f"/api/v1/documents/{document.id}/shares", identity=owner
    ).status_code == 404
    assert api_harness.request(
        "PUT",
        f"/api/v1/documents/{document.id}/shares/{other_user.user.id}",
        identity=owner,
    ).status_code == 404


def test_database_cleanup_failure_after_unlink_keeps_tombstone_and_retryable(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = api_harness.identity("databasecleanupowner")
    document = api_harness.create_document(owner)
    original_commit = Session.commit

    def fail_document_cleanup(session: Session) -> None:
        if any(isinstance(row, Document) for row in session.deleted):
            raise SQLAlchemyError("synthetic final cleanup failure")
        original_commit(session)

    monkeypatch.setattr(Session, "commit", fail_document_cleanup)
    response = api_harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", identity=owner
    )
    assert response.status_code == 500
    with pytest.raises(StoredFileNotFound):
        api_harness.storage.open_file(document.storage_key)
    with api_harness.sessions() as session:
        persisted = session.get(Document, document.id)
        assert persisted is not None and persisted.status == "deleting"

    assert api_harness.request(
        "GET", f"/api/v1/documents/{document.id}", identity=owner
    ).status_code == 404
    assert api_harness.request(
        "GET", f"/api/v1/documents/{document.id}/download", identity=owner
    ).status_code == 404

    monkeypatch.setattr(Session, "commit", original_commit)
    retry = api_harness.request(
        "DELETE", f"/api/v1/documents/{document.id}", identity=owner
    )
    assert retry.status_code == 204
    with api_harness.sessions() as session:
        assert session.get(Document, document.id) is None


def test_owner_can_grant_share(api_harness: APIHarness) -> None:
    owner = api_harness.identity("grantowner")
    recipient = api_harness.identity("grantrecipient")
    document = api_harness.create_document(owner)
    response = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert response.status_code == 201
    assert response.json()["user_id"] == str(recipient.user.id)
    with api_harness.sessions() as session:
        assert session.scalar(select(DocumentShare).where(
            DocumentShare.document_id == document.id,
            DocumentShare.recipient_user_id == recipient.user.id,
        )) is not None


@pytest.mark.parametrize("target", ["missing", "inactive", "owner"])
def test_share_grant_rejects_ineligible_targets_without_creating_access(
    api_harness: APIHarness,
    target: str,
) -> None:
    owner = api_harness.identity("eligibilityowner")
    recipient = api_harness.identity("eligibilityrecipient")
    document = api_harness.create_document(owner)
    target_id = {
        "missing": uuid4(),
        "inactive": recipient.user.id,
        "owner": owner.user.id,
    }[target]

    if target == "inactive":
        with api_harness.sessions() as session:
            inactive_user = session.get(User, recipient.user.id)
            assert inactive_user is not None
            inactive_user.is_active = False
            session.commit()

    response = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document.id}/shares/{target_id}",
        identity=owner,
    )
    assert response.status_code == (422 if target == "owner" else 404)

    with api_harness.sessions() as session:
        shares = session.scalars(
            select(DocumentShare).where(DocumentShare.document_id == document.id)
        ).all()
        assert shares == []

    if target == "inactive":
        # The test auth override deliberately permits the synthetic session;
        # no share grant means even that session receives no document access.
        response = api_harness.request(
            "GET", f"/api/v1/documents/{document.id}", identity=recipient
        )
        assert response.status_code == 404
        assert_private(response)


def test_active_share_target_can_read_metadata_and_download(
    api_harness: APIHarness,
) -> None:
    owner = api_harness.identity("eligibilityactiveowner")
    recipient = api_harness.identity("eligibilityactiveuser")
    document = api_harness.create_document(owner)

    response = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert response.status_code == 201

    metadata = api_harness.request(
        "GET", f"/api/v1/documents/{document.id}", identity=recipient
    )
    download = api_harness.request(
        "GET", f"/api/v1/documents/{document.id}/download", identity=recipient
    )
    assert metadata.status_code == 200
    assert metadata.json()["access"] == "shared"
    assert_private(metadata)
    assert download.status_code == 200
    assert download.content == VALID_PDF
    assert_private(download)


def test_duplicate_share_grant_returns_conflict(api_harness: APIHarness) -> None:
    owner = api_harness.identity("duplicateowner")
    recipient = api_harness.identity("duplicaterecipient")
    document = api_harness.create_document(owner, shared_with=recipient)
    response = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert response.status_code == 409
    with api_harness.sessions() as session:
        assert len(
            session.scalars(
                select(DocumentShare).where(
                    DocumentShare.document_id == document.id,
                    DocumentShare.recipient_user_id == recipient.user.id,
                )
            ).all()
        ) == 1


def test_share_unique_constraint_rejects_duplicate_database_rows(
    api_harness: APIHarness,
) -> None:
    owner = api_harness.identity("uniqueconstraintowner")
    recipient = api_harness.identity("uniqueconstraintrecipient")
    document = api_harness.create_document(owner, shared_with=recipient)

    with api_harness.sessions() as session:
        session.add(
            DocumentShare(
                document_id=document.id,
                recipient_user_id=recipient.user.id,
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()

    with api_harness.sessions() as session:
        assert len(
            session.scalars(
                select(DocumentShare).where(
                    DocumentShare.document_id == document.id,
                    DocumentShare.recipient_user_id == recipient.user.id,
                )
            ).all()
        ) == 1


def test_share_grant_maps_concurrent_integrity_conflict_to_409(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = api_harness.identity("concurrentgrantowner")
    recipient = api_harness.identity("concurrentgrantrecipient")
    document = api_harness.create_document(owner)
    original_commit = Session.commit

    def conflict_on_share_commit(session: Session) -> None:
        if any(isinstance(row, DocumentShare) for row in session.new):
            raise IntegrityError("duplicate share", {}, Exception("unique conflict"))
        original_commit(session)

    monkeypatch.setattr(Session, "commit", conflict_on_share_commit)
    response = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Document is already shared with this user"
    with api_harness.sessions() as session:
        assert session.scalar(
            select(DocumentShare).where(
                DocumentShare.document_id == document.id,
                DocumentShare.recipient_user_id == recipient.user.id,
            )
        ) is None


def test_owner_can_list_document_shares(api_harness: APIHarness) -> None:
    owner = api_harness.identity("sharelistowner")
    recipient = api_harness.identity("sharelistrecipient")
    document = api_harness.create_document(owner, shared_with=recipient)
    response = api_harness.request(
        "GET", f"/api/v1/documents/{document.id}/shares", identity=owner
    )
    assert response.status_code == 200
    assert response.json()[0]["user_id"] == str(recipient.user.id)


def test_owner_can_revoke_share(api_harness: APIHarness) -> None:
    owner = api_harness.identity("revokeowner")
    recipient = api_harness.identity("revokerecipient")
    document = api_harness.create_document(owner, shared_with=recipient)
    response = api_harness.request(
        "DELETE",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert response.status_code == 204
    with api_harness.sessions() as session:
        assert session.scalar(select(DocumentShare).where(
            DocumentShare.document_id == document.id,
            DocumentShare.recipient_user_id == recipient.user.id,
        )) is None


def test_revocation_removes_recipient_access_but_preserves_owner_access(
    api_harness: APIHarness,
) -> None:
    owner = api_harness.identity("revokeaccessowner")
    recipient = api_harness.identity("revokeaccessrecipient")
    outsider = api_harness.identity("revokeaccessoutsider")
    document = api_harness.create_document(owner)

    grant = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert grant.status_code == 201
    assert api_harness.request(
        "GET", f"/api/v1/documents/{document.id}", identity=recipient
    ).status_code == 200
    assert api_harness.request(
        "GET", f"/api/v1/documents/{document.id}/download", identity=recipient
    ).status_code == 200

    revoked = api_harness.request(
        "DELETE",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert revoked.status_code == 204

    for path in (
        f"/api/v1/documents/{document.id}",
        f"/api/v1/documents/{document.id}/download",
    ):
        recipient_response = api_harness.request(path=path, method="GET", identity=recipient)
        outsider_response = api_harness.request(path=path, method="GET", identity=outsider)
        owner_response = api_harness.request(path=path, method="GET", identity=owner)
        assert recipient_response.status_code == 404
        assert outsider_response.status_code == 404
        assert owner_response.status_code == 200
        assert_private(recipient_response)
        assert_private(outsider_response)
        assert_private(owner_response)


def test_share_revoke_requires_csrf_and_preserves_grant(
    api_harness: APIHarness,
) -> None:
    owner = api_harness.identity("csrfrevocationowner")
    recipient = api_harness.identity("csrfrevocationrecipient")
    document = api_harness.create_document(owner, shared_with=recipient)

    response = api_harness.request(
        "DELETE",
        f"/api/v1/documents/{document.id}/shares/{recipient.user.id}",
        identity=owner,
        csrf=False,
    )
    assert response.status_code == 403
    with api_harness.sessions() as session:
        assert session.scalar(
            select(DocumentShare).where(
                DocumentShare.document_id == document.id,
                DocumentShare.recipient_user_id == recipient.user.id,
            )
        ) is not None


def test_document_audit_logs_redact_sensitive_data_on_success_and_failure_paths(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    owner = api_harness.identity("auditredactionowner")
    recipient = api_harness.identity("auditredactionrecipient")
    outsider = api_harness.identity("auditredactionoutsider")
    password_marker = "PASSWORD_SECRET_AUDIT_MARKER"
    successful_filename = "submitted-filename-secret-marker.pdf"
    rejected_filename = "rejected-filename-secret-marker.pdf"
    successful_file_marker = b"PDF_CONTENT_SECRET_AUDIT_MARKER"
    rejected_file_marker = b"REJECTED_PDF_CONTENT_SECRET_AUDIT_MARKER"
    successful_pdf = VALID_PDF + b"\n% " + successful_file_marker + b"\n"
    rejected_pdf = b"%PDF-1.4\n" + rejected_file_marker

    with api_harness.sessions() as session:
        persisted_owner = session.get(User, owner.user.id)
        assert persisted_owner is not None
        persisted_owner.password_hash = password_marker
        session.commit()

    monkeypatch.setattr(security_logger, "propagate", True)
    caplog.set_level(logging.INFO, logger=security_logger.name)
    caplog.clear()

    uploaded = upload(
        api_harness,
        owner,
        filename=successful_filename,
        content=successful_pdf,
    )
    assert uploaded.status_code == 201
    document_id = UUID(uploaded.json()["id"])
    with api_harness.sessions() as session:
        document = session.get(Document, document_id)
        assert document is not None
        storage_key = str(document.storage_key)

    rejected = upload(
        api_harness,
        owner,
        filename=rejected_filename,
        content=rejected_pdf,
    )
    assert rejected.status_code == 422

    downloaded = api_harness.request(
        "GET", f"/api/v1/documents/{document_id}/download", identity=owner
    )
    assert downloaded.status_code == 200

    granted = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document_id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert granted.status_code == 201
    denied_grant = api_harness.request(
        "PUT",
        f"/api/v1/documents/{document_id}/shares/{recipient.user.id}",
        identity=outsider,
    )
    assert denied_grant.status_code == 404
    revoked = api_harness.request(
        "DELETE",
        f"/api/v1/documents/{document_id}/shares/{recipient.user.id}",
        identity=owner,
    )
    assert revoked.status_code == 204

    def fail_delete(storage_key: UUID) -> None:
        raise StorageError("synthetic failure includes no user data")

    monkeypatch.setattr(api_harness.storage, "delete_file", fail_delete)
    failed_delete = api_harness.request(
        "DELETE", f"/api/v1/documents/{document_id}", identity=owner
    )
    assert failed_delete.status_code == 500

    records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == security_logger.name
    ]
    assert {
        (record["event"], record["outcome"]) for record in records
    } >= {
        ("upload.accepted", "success"),
        ("upload.rejected", "denied"),
        ("download.allowed", "success"),
        ("share.granted", "success"),
        ("access.denied", "denied"),
        ("share.revoked", "success"),
        ("delete.started", "success"),
        ("delete.failed", "failure"),
    }
    allowed_fields = {
        "timestamp",
        "event",
        "outcome",
        "actor_id",
        "target_id",
        "source_ip",
        "reason",
    }
    assert all(set(record) == allowed_fields for record in records)

    forbidden_values = (
        successful_file_marker.decode(),
        rejected_file_marker.decode(),
        successful_filename,
        rejected_filename,
        password_marker,
        owner.session_token,
        owner.csrf_token,
        recipient.session_token,
        recipient.csrf_token,
        outsider.session_token,
        outsider.csrf_token,
        str(api_harness.storage_root.resolve()),
        storage_key,
    )
    serialized_records = json.dumps(records, sort_keys=True)
    for forbidden_value in forbidden_values:
        assert forbidden_value not in serialized_records


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_shared_recipient_cannot_manage_shares(
    api_harness: APIHarness,
    method: str,
) -> None:
    owner = api_harness.identity("manageowner")
    recipient = api_harness.identity("managerecipient")
    other_user = api_harness.identity("manageother")
    document = api_harness.create_document(owner, shared_with=recipient)
    suffix = "/shares" if method == "GET" else f"/shares/{other_user.user.id}"
    response = api_harness.request(
        method,
        f"/api/v1/documents/{document.id}{suffix}",
        identity=recipient,
    )
    assert response.status_code == 404


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
@pytest.mark.parametrize("role", ["user", "administrator"])
def test_non_owner_cannot_manage_shares(
    api_harness: APIHarness,
    method: str,
    role: str,
) -> None:
    owner = api_harness.identity("noshareowner")
    requester = api_harness.identity(f"noshare{role}", role)
    target = api_harness.identity("nosharetarget")
    document = api_harness.create_document(owner)
    suffix = "/shares" if method == "GET" else f"/shares/{target.user.id}"
    response = api_harness.request(
        method,
        f"/api/v1/documents/{document.id}{suffix}",
        identity=requester,
    )
    assert response.status_code == 404


def test_upload_database_failure_compensates_promoted_file(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = api_harness.identity("compensateowner")
    original_commit = Session.commit

    def fail_commit(session: Session) -> None:
        if session.new and any(isinstance(row, Document) for row in session.new):
            raise SQLAlchemyError("synthetic persistence failure")
        original_commit(session)

    monkeypatch.setattr(Session, "commit", fail_commit)
    response = upload(api_harness, owner)
    assert response.status_code == 500
    assert list(api_harness.storage_root.iterdir()) == []
