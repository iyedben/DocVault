"""Authenticated document upload, access, deletion, and sharing endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator, Generator
from contextlib import suppress
from typing import Annotated, Literal
from urllib.parse import quote
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import StreamingResponse

from app.api.dependencies import get_current_auth, require_csrf
from app.api.document_schemas import DocumentResponse, DocumentShareResponse
from app.audit import record_security_event
from app.core.config import (
    DOCUMENT_MULTIPART_OVERHEAD_BYTES,
    DocumentSettings,
)
from app.db.session import get_db
from app.middleware.document_limits import DOCUMENTS_PATH
from app.models import Document, DocumentShare, User
from app.security.document_validation import (
    FilenameValidationError,
    PDFContentValidator,
    PDFSizeLimitError,
    PDFValidationError,
    validate_pdf_structure,
)
from app.security.sessions import AuthContext
from app.services.documents import (
    DocumentAccess,
    get_accessible_document,
    get_active_recipient,
    get_owned_document,
    list_accessible_documents,
)
from app.storage import (
    EmptyDocumentError,
    PrivateDocumentStorage,
    StorageError,
    StorageIntegrityError,
    StorageLimitExceeded,
    StoredFileNotFound,
)

router = APIRouter(prefix=DOCUMENTS_PATH, tags=["documents"])
CHUNK_SIZE_BYTES = 64 * 1024


def get_document_storage() -> Generator[PrivateDocumentStorage, None, None]:
    """Open a request-scoped storage handle rooted at the configured volume."""
    settings = DocumentSettings.from_environment()
    storage = PrivateDocumentStorage(
        settings.storage_root,
        max_size_bytes=settings.max_document_size_bytes,
    )
    try:
        yield storage
    finally:
        storage.close()


def _document_response(
    document: Document,
    access: DocumentAccess,
) -> DocumentResponse:
    return DocumentResponse(
        id=document.id,
        display_filename=document.display_filename,
        media_type=document.media_type,  # type: ignore[arg-type]
        file_size=document.file_size,
        created_at=document.created_at,
        access=access,
    )


def _audit(
    event: str,
    outcome: str,
    actor: User,
    request: Request,
    *,
    document: Document | None = None,
    reason: str | None = None,
) -> None:
    record_security_event(
        event,
        outcome,
        actor_id=str(actor.id),
        target_id=str(document.id) if document is not None else None,
        source_ip=request.client.host if request.client else None,
        reason=reason,
    )


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")


def _safe_content_disposition(filename: str) -> str:
    fallback = "".join(
        character
        if character.isascii() and (character.isalnum() or character in "-._")
        else "_"
        for character in filename
    )
    if not fallback:
        fallback = "document.pdf"
    encoded = quote(filename, safe="")
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"


async def _stream_file(file_object) -> AsyncIterator[bytes]:
    try:
        while chunk := file_object.read(CHUNK_SIZE_BYTES):
            yield chunk
    finally:
        file_object.close()


async def _close_form(form) -> None:
    await form.close()


@router.post("", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    auth: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[PrivateDocumentStorage, Depends(get_document_storage)],
) -> DocumentResponse:
    settings = DocumentSettings.from_environment()
    try:
        form = await request.form(
            max_files=1,
            max_fields=0,
            max_part_size=DOCUMENT_MULTIPART_OVERHEAD_BYTES,
        )
    except StarletteHTTPException:
        _audit(
            "upload.rejected",
            "denied",
            auth.user,
            request,
            reason="invalid_multipart",
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid multipart upload",
        ) from None

    staged = None
    promoted_key: UUID | None = None
    document_persisted = False
    try:
        files = form.getlist("file")
        if len(form) != 1 or len(files) != 1 or not isinstance(files[0], StarletteUploadFile):
            _audit(
                "upload.rejected",
                "denied",
                auth.user,
                request,
                reason="invalid_multipart_shape",
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Exactly one file field named 'file' is required",
            )

        upload = files[0]
        filename = upload.filename or ""
        try:
            validator = PDFContentValidator(
                filename,
                upload.content_type,
                max_size_bytes=settings.max_document_size_bytes,
            )
        except FilenameValidationError:
            _audit(
                "upload.rejected",
                "denied",
                auth.user,
                request,
                reason="invalid_filename",
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid document filename",
            ) from None
        except PDFValidationError:
            _audit(
                "upload.rejected",
                "denied",
                auth.user,
                request,
                reason="unsupported_document_type",
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Only valid PDF documents are supported",
            ) from None

        staged = storage.create_staged_file()
        file_size = 0
        while chunk := await upload.read(CHUNK_SIZE_BYTES):
            try:
                validator.feed(chunk)
            except PDFSizeLimitError:
                _audit(
                    "upload.rejected",
                    "denied",
                    auth.user,
                    request,
                    reason="document_size_limit",
                )
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="Document exceeds the maximum permitted size",
                ) from None
            except PDFValidationError:
                _audit(
                    "upload.rejected",
                    "denied",
                    auth.user,
                    request,
                    reason="invalid_pdf_content",
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Invalid PDF document",
                ) from None
            file_size = storage.write_chunks(staged, [chunk])

        try:
            validated_size = validator.finish()
        except PDFValidationError:
            _audit(
                "upload.rejected",
                "denied",
                auth.user,
                request,
                reason="invalid_pdf_content",
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid PDF document",
            ) from None

        try:
            validate_pdf_structure(upload.file)
        except PDFValidationError:
            _audit(
                "upload.rejected",
                "denied",
                auth.user,
                request,
                reason="invalid_pdf_structure",
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid or incomplete PDF document",
            ) from None

        request_size = getattr(request.state, "document_request_bytes", None)
        if request_size is not None and request_size - file_size > DOCUMENT_MULTIPART_OVERHEAD_BYTES:
            _audit(
                "upload.rejected",
                "denied",
                auth.user,
                request,
                reason="multipart_overhead_limit",
            )
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Multipart request overhead exceeds the permitted limit",
            )
        if validated_size != file_size:
            raise StorageIntegrityError("Validated byte count differs from stored byte count")

        promoted_key = uuid4()
        storage.promote(staged, promoted_key)
        staged = None

        document = Document(
            owner_id=auth.user.id,
            display_filename=filename,
            media_type="application/pdf",
            file_size=file_size,
            storage_key=promoted_key,
            status="active",
        )
        db.add(document)
        db.commit()
        document_persisted = True
        _audit("upload.accepted", "success", auth.user, request, document=document)
        return _document_response(document, "owner")
    except OSError:
        _audit(
            "upload.rejected",
            "failure",
            auth.user,
            request,
            reason="upload_read_failure",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document could not be read",
        ) from None
    except HTTPException:
        raise
    except (EmptyDocumentError, StorageLimitExceeded):
        _audit(
            "upload.rejected",
            "denied",
            auth.user,
            request,
            reason="document_size_or_empty",
        )
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Document is empty or exceeds the maximum permitted size",
        ) from None
    except SQLAlchemyError:
        db.rollback()
        compensation_failed = False
        if promoted_key is not None:
            try:
                storage.delete_file(promoted_key)
            except StorageError:
                compensation_failed = True
        if staged is not None:
            try:
                storage.delete_staged_file(staged)
            except StorageError:
                compensation_failed = True
        _audit(
            "upload.rejected",
            "failure",
            auth.user,
            request,
            reason=(
                "database_failure_cleanup_failed"
                if compensation_failed
                else "database_failure"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document could not be saved",
        ) from None
    except StorageError:
        _audit(
            "upload.rejected",
            "failure",
            auth.user,
            request,
            reason="storage_failure",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document storage operation failed",
        ) from None
    finally:
        if staged is not None:
            with suppress(StorageError):
                # Preserve the original upload failure if cleanup also fails.
                storage.delete_staged_file(staged)
        if promoted_key is not None and not document_persisted:
            with suppress(StorageError):
                # Do not replace the original failure with a compensation error.
                storage.delete_file(promoted_key)
        await _close_form(form)


@router.get("", response_model=list[DocumentResponse])
async def list_documents(
    auth: Annotated[AuthContext, Depends(get_current_auth)],
    db: Annotated[Session, Depends(get_db)],
) -> list[DocumentResponse]:
    return _list_documents(auth, db)


def _list_documents(
    auth: AuthContext,
    db: Session,
) -> list[DocumentResponse]:
    rows = list_accessible_documents(db, auth.user.id)
    db.commit()
    return [_document_response(document, access) for document, access in rows]


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document_metadata(
    document_id: UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(get_current_auth)],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentResponse:
    return _get_document_metadata(document_id, request, auth, db)


def _get_document_metadata(
    document_id: UUID,
    request: Request,
    auth: AuthContext,
    db: Session,
) -> DocumentResponse:
    document = get_accessible_document(db, document_id, auth.user.id, lock=True)
    if document is None:
        db.rollback()
        _audit("access.denied", "denied", auth.user, request, reason="document_unavailable")
        raise _not_found()
    access: Literal["owner", "shared"] = (
        "owner" if document.owner_id == auth.user.id else "shared"
    )
    db.commit()
    return _document_response(document, access)


@router.get("/{document_id}/download")
async def download_document(
    document_id: UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(get_current_auth)],
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[PrivateDocumentStorage, Depends(get_document_storage)],
) -> StreamingResponse:
    return _download_document(document_id, request, auth, db, storage)


def _download_document(
    document_id: UUID,
    request: Request,
    auth: AuthContext,
    db: Session,
    storage: PrivateDocumentStorage,
) -> StreamingResponse:
    document = get_accessible_document(db, document_id, auth.user.id, lock=True)
    if document is None:
        db.rollback()
        _audit("download.denied", "denied", auth.user, request, reason="document_unavailable")
        raise _not_found()

    try:
        file_object = storage.open_file(document.storage_key)
    except (StoredFileNotFound, StorageIntegrityError):
        db.commit()
        _audit(
            "download.denied",
            "denied",
            auth.user,
            request,
            document=document,
            reason="stored_file_unavailable",
        )
        raise _not_found() from None
    except StorageError:
        db.rollback()
        _audit(
            "download.denied",
            "failure",
            auth.user,
            request,
            document=document,
            reason="storage_failure",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document could not be opened",
        ) from None

    try:
        db.commit()
    except SQLAlchemyError:
        file_object.close()
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document could not be opened",
        ) from None

    _audit("download.allowed", "success", auth.user, request, document=document)
    return StreamingResponse(
        _stream_file(file_object),
        media_type="application/pdf",
        headers={
            "Content-Disposition": _safe_content_disposition(document.display_filename),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    document_id: UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[PrivateDocumentStorage, Depends(get_document_storage)],
) -> Response:
    return _delete_document(document_id, request, auth, db, storage)


def _delete_document(
    document_id: UUID,
    request: Request,
    auth: AuthContext,
    db: Session,
    storage: PrivateDocumentStorage,
) -> Response:
    document = get_owned_document(
        db,
        document_id,
        auth.user.id,
        include_deleting=True,
        lock=True,
    )
    if document is None:
        db.rollback()
        _audit("access.denied", "denied", auth.user, request, reason="delete_not_owned")
        raise _not_found()

    if document.status == "active":
        document.status = "deleting"
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            _audit(
                "delete.failed",
                "failure",
                auth.user,
                request,
                document=document,
                reason="tombstone_commit_failed",
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Document deletion could not be started",
            ) from None

    _audit("delete.started", "success", auth.user, request, document=document)
    try:
        file_removed = storage.delete_file(document.storage_key)
    except StorageError:
        db.rollback()
        _audit(
            "delete.failed",
            "failure",
            auth.user,
            request,
            document=document,
            reason="filesystem_failure",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document deletion can be retried",
        ) from None

    try:
        db.execute(delete(DocumentShare).where(DocumentShare.document_id == document.id))
        db.delete(document)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        _audit(
            "delete.failed",
            "failure",
            auth.user,
            request,
            document=document,
            reason="database_cleanup_failed",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document deletion can be retried",
        ) from None

    _audit(
        "delete.completed",
        "success",
        auth.user,
        request,
        document=document,
        reason="file_already_missing" if not file_removed else None,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{document_id}/shares", response_model=list[DocumentShareResponse])
async def list_document_shares(
    document_id: UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(get_current_auth)],
    db: Annotated[Session, Depends(get_db)],
) -> list[DocumentShareResponse]:
    return _list_document_shares(document_id, request, auth, db)


def _list_document_shares(
    document_id: UUID,
    request: Request,
    auth: AuthContext,
    db: Session,
) -> list[DocumentShareResponse]:
    document = get_owned_document(db, document_id, auth.user.id, lock=True)
    if document is None:
        db.rollback()
        _audit("access.denied", "denied", auth.user, request, reason="shares_not_owned")
        raise _not_found()
    rows = db.execute(
        select(DocumentShare, User)
        .join(User, User.id == DocumentShare.recipient_user_id)
        .where(
            DocumentShare.document_id == document.id,
            User.is_active.is_(True),
        )
        .order_by(User.username.asc(), User.id.asc())
    ).all()
    db.commit()
    return [
        DocumentShareResponse(
            user_id=recipient.id,
            username=recipient.username,
            created_at=share.created_at,
        )
        for share, recipient in rows
    ]


@router.put(
    "/{document_id}/shares/{user_id}",
    response_model=DocumentShareResponse,
    status_code=status.HTTP_201_CREATED,
)
async def grant_document_share(
    document_id: UUID,
    user_id: UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[Session, Depends(get_db)],
) -> DocumentShareResponse:
    return _grant_document_share(document_id, user_id, request, auth, db)


def _grant_document_share(
    document_id: UUID,
    user_id: UUID,
    request: Request,
    auth: AuthContext,
    db: Session,
) -> DocumentShareResponse:
    document = get_owned_document(db, document_id, auth.user.id, lock=True)
    if document is None:
        db.rollback()
        _audit("access.denied", "denied", auth.user, request, reason="share_not_owned")
        raise _not_found()
    recipient = get_active_recipient(db, user_id)
    if recipient is None:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if recipient.id == auth.user.id:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="A document cannot be shared with its owner",
        )

    existing_share = db.scalar(
        select(DocumentShare).where(
            DocumentShare.document_id == document.id,
            DocumentShare.recipient_user_id == recipient.id,
        )
    )
    if existing_share is not None:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Document is already shared with this user",
        )

    share = DocumentShare(document_id=document.id, recipient_user_id=recipient.id)
    db.add(share)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Document is already shared with this user",
        ) from None
    _audit("share.granted", "success", auth.user, request, document=document)
    return DocumentShareResponse(
        user_id=recipient.id,
        username=recipient.username,
        created_at=share.created_at,
    )


@router.delete(
    "/{document_id}/shares/{user_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def revoke_document_share(
    document_id: UUID,
    user_id: UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    return _revoke_document_share(document_id, user_id, request, auth, db)


def _revoke_document_share(
    document_id: UUID,
    user_id: UUID,
    request: Request,
    auth: AuthContext,
    db: Session,
) -> Response:
    document = get_owned_document(db, document_id, auth.user.id, lock=True)
    if document is None:
        db.rollback()
        _audit("access.denied", "denied", auth.user, request, reason="revoke_not_owned")
        raise _not_found()
    share = db.scalar(
        select(DocumentShare).where(
            DocumentShare.document_id == document.id,
            DocumentShare.recipient_user_id == user_id,
        )
    )
    if share is None:
        db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    db.delete(share)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Share could not be revoked",
        ) from None
    _audit("share.revoked", "success", auth.user, request, document=document)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
