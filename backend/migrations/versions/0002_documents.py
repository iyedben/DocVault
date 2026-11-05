"""Create document metadata and explicit document shares."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_documents"
down_revision = "0001_identity_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("owner_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("display_filename", sa.String(length=255), nullable=False),
        sa.Column("media_type", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("storage_key", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "media_type = 'application/pdf'", name="ck_documents_media_type_pdf"
        ),
        sa.CheckConstraint(
            "file_size > 0 AND file_size <= 10485760",
            name="ck_documents_file_size_range",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'deleting')", name="ck_documents_status_allowed"
        ),
        sa.CheckConstraint(
            "length(display_filename) BETWEEN 1 AND 255",
            name="ck_documents_display_filename_length",
        ),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name="fk_documents_owner_id_users", ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key", name="uq_documents_storage_key"),
    )
    op.create_index(
        "ix_documents_owner_status", "documents", ["owner_id", "status"], unique=False
    )
    op.create_index("ix_documents_status", "documents", ["status"], unique=False)

    op.create_table(
        "document_shares",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("document_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("recipient_user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name="fk_document_shares_document_id_documents",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["recipient_user_id"],
            ["users.id"],
            name="fk_document_shares_recipient_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "document_id",
            "recipient_user_id",
            name="uq_document_shares_document_recipient",
        ),
    )
    op.create_index(
        "ix_document_shares_recipient_user_id",
        "document_shares",
        ["recipient_user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_document_shares_recipient_user_id", table_name="document_shares"
    )
    op.drop_table("document_shares")
    op.drop_index("ix_documents_status", table_name="documents")
    op.drop_index("ix_documents_owner_status", table_name="documents")
    op.drop_table("documents")
