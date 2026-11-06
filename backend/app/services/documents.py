"""Database queries that enforce document ownership and explicit sharing."""

from typing import Literal
from uuid import UUID

from sqlalchemy import case, exists, or_, select
from sqlalchemy.orm import Session

from app.models import Document, DocumentShare, User

DocumentAccess = Literal["owner", "shared"]


def accessible_document_statement(document_id: UUID, actor_id: UUID):
    """Select an active document only when the actor owns it or has a share."""
    explicit_share = exists(
        select(DocumentShare.id).where(
            DocumentShare.document_id == Document.id,
            DocumentShare.recipient_user_id == actor_id,
        )
    )
    return select(Document).where(
        Document.id == document_id,
        Document.status == "active",
        or_(Document.owner_id == actor_id, explicit_share),
    )


def get_accessible_document(
    db: Session,
    document_id: UUID,
    actor_id: UUID,
    *,
    lock: bool = False,
) -> Document | None:
    statement = accessible_document_statement(document_id, actor_id)
    if lock:
        statement = statement.with_for_update(read=True, of=Document)
    return db.scalar(statement)


def get_owned_document(
    db: Session,
    document_id: UUID,
    owner_id: UUID,
    *,
    include_deleting: bool = False,
    lock: bool = False,
) -> Document | None:
    statement = select(Document).where(
        Document.id == document_id,
        Document.owner_id == owner_id,
    )
    if not include_deleting:
        statement = statement.where(Document.status == "active")
    if lock:
        statement = statement.with_for_update(of=Document)
    return db.scalar(statement)


def list_accessible_documents(
    db: Session, actor_id: UUID
) -> list[tuple[Document, DocumentAccess]]:
    explicit_share = exists(
        select(DocumentShare.id).where(
            DocumentShare.document_id == Document.id,
            DocumentShare.recipient_user_id == actor_id,
        )
    )
    access_label = case(
        (Document.owner_id == actor_id, "owner"),
        else_="shared",
    ).label("access")
    statement = (
        select(Document, access_label)
        .where(
            Document.status == "active",
            or_(Document.owner_id == actor_id, explicit_share),
        )
        .order_by(Document.created_at.desc(), Document.id.asc())
        .with_for_update(read=True, of=Document)
    )
    return [
        (document, access)
        for document, access in db.execute(statement).all()
    ]


def get_active_recipient(db: Session, user_id: UUID) -> User | None:
    statement = (
        select(User)
        .where(User.id == user_id, User.is_active.is_(True))
        .with_for_update(read=True, of=User)
    )
    return db.scalar(statement)
