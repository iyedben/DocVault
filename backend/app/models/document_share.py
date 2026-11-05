"""Explicit document read grants to recipient users."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.user import utcnow

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.user import User


class DocumentShare(Base):
    """A unique grant allowing a recipient to access a document."""

    __tablename__ = "document_shares"
    __table_args__ = (
        UniqueConstraint(
            "document_id", "recipient_user_id", name="uq_document_shares_document_recipient"
        ),
        Index("ix_document_shares_recipient_user_id", "recipient_user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "documents.id",
            name="fk_document_shares_document_id_documents",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    recipient_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_document_shares_recipient_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )

    document: Mapped["Document"] = relationship(back_populates="shares")
    recipient: Mapped["User"] = relationship(back_populates="document_shares")
