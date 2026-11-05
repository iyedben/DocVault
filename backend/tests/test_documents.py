"""Tests for document metadata and explicit sharing constraints."""

import uuid

import pytest
from app.core.config import DEFAULT_MAX_DOCUMENT_SIZE_BYTES
from app.models import Document, DocumentShare, Role, User
from sqlalchemy import create_engine, delete, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


def make_user(session: Session, username: str) -> User:
    role = session.scalar(select(Role).where(Role.name == "user"))
    assert role is not None
    user = User(username=username, password_hash="test-hash", role=role)
    session.add(user)
    return user


@pytest.fixture
def foreign_key_session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    from app.db.base import Base

    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        session.add_all([Role(name="user"), Role(name="administrator")])
        session.commit()
        yield session
    engine.dispose()


def make_document(owner: User, **overrides: object) -> Document:
    values: dict[str, object] = {
        "owner": owner,
        "display_filename": "report.pdf",
        "media_type": "application/pdf",
        "file_size": 128,
    }
    values.update(overrides)
    return Document(**values)  # type: ignore[arg-type]


def test_document_model_construction_and_relationships(db_session: Session) -> None:
    owner = make_user(db_session, "documentowner")
    document = make_document(owner)
    db_session.add(document)
    db_session.commit()
    db_session.refresh(document)

    assert isinstance(document.id, uuid.UUID)
    assert document.owner_id == owner.id
    assert document.owner is owner
    assert document in owner.owned_documents
    assert document.display_filename == "report.pdf"
    assert document.media_type == "application/pdf"
    assert document.file_size == 128
    assert document.status == "active"
    assert document.created_at is not None
    assert isinstance(document.storage_key, uuid.UUID)
    assert str(document.storage_key) not in document.display_filename


def test_document_share_model_relationships(db_session: Session) -> None:
    owner = make_user(db_session, "shareowner")
    recipient = make_user(db_session, "sharerecipient")
    document = make_document(owner)
    share = DocumentShare(document=document, recipient=recipient)
    db_session.add_all([document, share])
    db_session.commit()

    assert isinstance(share.id, uuid.UUID)
    assert share.document_id == document.id
    assert share.recipient_user_id == recipient.id
    assert share.document is document
    assert share.recipient is recipient
    assert share in document.shares
    assert share in recipient.document_shares
    assert share.created_at is not None


@pytest.mark.parametrize("status", ["deleted", "pending", "ACTIVE", ""])
def test_document_rejects_invalid_lifecycle_status(db_session: Session, status: str) -> None:
    document = make_document(make_user(db_session, "statusowner"), status=status)
    db_session.add(document)

    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


@pytest.mark.parametrize("media_type", ["application/octet-stream", "image/pdf", ""])
def test_document_rejects_invalid_media_type(db_session: Session, media_type: str) -> None:
    document = make_document(make_user(db_session, "mediaowner"), media_type=media_type)
    db_session.add(document)

    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


@pytest.mark.parametrize("file_size", [0, -1, DEFAULT_MAX_DOCUMENT_SIZE_BYTES + 1])
def test_document_rejects_invalid_file_size(db_session: Session, file_size: int) -> None:
    document = make_document(make_user(db_session, "sizeowner"), file_size=file_size)
    db_session.add(document)

    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_document_accepts_maximum_permitted_file_size(db_session: Session) -> None:
    document = make_document(
        make_user(db_session, "maxsizeowner"),
        file_size=DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
    )
    db_session.add(document)
    db_session.commit()

    assert document.file_size == DEFAULT_MAX_DOCUMENT_SIZE_BYTES


def test_document_accepts_deleting_status(db_session: Session) -> None:
    document = make_document(make_user(db_session, "deletingowner"), status="deleting")
    db_session.add(document)
    db_session.commit()

    assert document.status == "deleting"


@pytest.mark.parametrize("display_filename", ["", "x" * 256])
def test_document_rejects_invalid_display_filename(
    db_session: Session, display_filename: str
) -> None:
    document = make_document(
        make_user(db_session, "filenameowner"), display_filename=display_filename
    )
    db_session.add(document)

    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_document_rejects_duplicate_storage_key(db_session: Session) -> None:
    owner = make_user(db_session, "keyowner")
    opaque_key = uuid.uuid4()
    first = make_document(owner, storage_key=opaque_key)
    db_session.add(first)
    db_session.commit()

    second = make_document(owner, storage_key=opaque_key)
    db_session.add(second)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_document_share_rejects_duplicate_document_recipient_grant(
    db_session: Session,
) -> None:
    owner = make_user(db_session, "grantowner")
    recipient = make_user(db_session, "grantrecipient")
    document = make_document(owner)
    first = DocumentShare(document=document, recipient=recipient)
    db_session.add_all([document, first])
    db_session.commit()

    db_session.add(DocumentShare(document=document, recipient=recipient))
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


@pytest.mark.parametrize("reference", ["document_owner", "share_document", "share_recipient"])
def test_document_foreign_keys_reject_missing_references(
    foreign_key_session: Session, reference: str
) -> None:
    session = foreign_key_session
    if reference == "document_owner":
        session.add(
            Document(
                owner_id=uuid.uuid4(),
                display_filename="report.pdf",
                media_type="application/pdf",
                file_size=128,
            )
        )
    else:
        recipient = make_user(session, f"validrecipient{reference}")
        session.add(recipient)
        session.flush()
        if reference == "share_document":
            session.add(
                DocumentShare(document_id=uuid.uuid4(), recipient_user_id=recipient.id)
            )
        else:
            owner = make_user(session, "validshareowner")
            document = make_document(owner)
            session.add(document)
            session.flush()
            session.add(
                DocumentShare(document_id=document.id, recipient_user_id=uuid.uuid4())
            )

    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_document_and_share_deletes_are_restricted_by_foreign_keys(
    foreign_key_session: Session,
) -> None:
    session = foreign_key_session
    owner = make_user(session, "restrictowner")
    recipient = make_user(session, "restrictrecipient")
    document = make_document(owner)
    share = DocumentShare(document=document, recipient=recipient)
    session.add_all([owner, recipient, document, share])
    session.commit()

    with pytest.raises(IntegrityError):
        session.execute(delete(Document).where(Document.id == document.id))
    session.rollback()

    with pytest.raises(IntegrityError):
        session.execute(delete(User).where(User.id == owner.id))
    session.rollback()

    with pytest.raises(IntegrityError):
        session.execute(delete(User).where(User.id == recipient.id))
    session.rollback()
