"""Document metadata stored separately from private file bytes."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.config import DEFAULT_MAX_DOCUMENT_SIZE_BYTES
from app.db.base import Base
from app.models.user import utcnow

if TYPE_CHECKING:
    from app.models.document_share import DocumentShare
    from app.models.user import User


DocumentStatus = Literal["active", "deleting"]


class Document(Base):
    """Database metadata and ownership for one privately stored document."""

    __tablename__ = "documents"
    __table_args__ = (
        CheckConstraint(
            "media_type = 'application/pdf'", name="ck_documents_media_type_pdf"
        ),
        CheckConstraint(
            f"file_size > 0 AND file_size <= {DEFAULT_MAX_DOCUMENT_SIZE_BYTES}",
            name="ck_documents_file_size_range",
        ),
        CheckConstraint(
            "status IN ('active', 'deleting')", name="ck_documents_status_allowed"
        ),
        CheckConstraint(
            "length(display_filename) BETWEEN 1 AND 255",
            name="ck_documents_display_filename_length",
        ),
        UniqueConstraint("storage_key", name="uq_documents_storage_key"),
        Index("ix_documents_owner_status", "owner_id", "status"),
        Index("ix_documents_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", name="fk_documents_owner_id_users", ondelete="RESTRICT"),
        nullable=False,
    )
    display_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_key: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), nullable=False, default=uuid.uuid4
    )
    status: Mapped[DocumentStatus] = mapped_column(
        String(16), nullable=False, default="active", server_default="active"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )

    owner: Mapped["User"] = relationship(back_populates="owned_documents")
    shares: Mapped[list["DocumentShare"]] = relationship(
        back_populates="document", passive_deletes="all"
    )
