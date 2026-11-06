"""Pure filename and PDF validation for future document upload handling."""

import ntpath
import unicodedata
from collections.abc import Iterable
from typing import BinaryIO

from pypdf import PdfReader
from pypdf.errors import PyPdfError

from app.core.config import DEFAULT_MAX_DOCUMENT_SIZE_BYTES

MAX_DISPLAY_FILENAME_BYTES = 255
PDF_SIGNATURE = b"%PDF-"
PDF_MEDIA_TYPE = "application/pdf"
_PATH_SEPARATOR_LOOKALIKES = frozenset("\u2044\u2215\u29f8\uff0f\uff3c")
_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2066\u2067\u2068\u2069"
)


class FilenameValidationError(ValueError):
    """Raised when an original filename is not safe display metadata."""


class PDFValidationError(ValueError):
    """Raised when uploaded bytes do not satisfy the configured PDF policy."""


class PDFSizeLimitError(PDFValidationError):
    """Raised when streamed PDF content exceeds its configured byte limit."""


def validate_pdf_structure(stream: BinaryIO) -> None:
    """Require a readable PDF catalog and page tree without rendering content.

    The caller must enforce the byte limit before calling this function and pass
    a seekable binary stream. ``PdfReader`` parses the supplied stream directly;
    it does not need a path or an application-owned full-file byte copy. This is
    structural validation only, not malware detection or content sanitization.
    """
    reader: PdfReader | None = None
    try:
        stream.seek(0)
        reader = PdfReader(stream, strict=True)
        if reader.is_encrypted:
            raise PDFValidationError("Encrypted PDF documents are not supported")

        catalog = reader.trailer.get("/Root")
        if catalog is None or catalog.get("/Type") != "/Catalog":
            raise PDFValidationError("PDF catalog is missing or invalid")

        # Resolve the page tree without rendering pages or processing actions.
        _ = reader.pages
    except PDFValidationError:
        raise
    except (
        PyPdfError,
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        OverflowError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        # Parser exceptions can contain untrusted document data. Expose only a
        # stable validation error to callers and logs.
        raise PDFValidationError("PDF structure is invalid or incomplete") from None
    finally:
        if reader is not None:
            reader.close()


def validate_display_filename(original_filename: str) -> str:
    """Accept and preserve a safe display filename; never produce a storage path.

    Unsafe names are rejected instead of being rewritten into a different name.
    The returned value is metadata only and must never be used for filesystem
    addressing.
    """
    if not isinstance(original_filename, str) or not original_filename:
        raise FilenameValidationError("Filename must not be empty")
    if original_filename != original_filename.strip():
        raise FilenameValidationError("Filename has unsafe surrounding whitespace")
    if "/" in original_filename or "\\" in original_filename:
        raise FilenameValidationError("Filename must not contain path separators")
    if ntpath.splitdrive(original_filename)[0]:
        raise FilenameValidationError("Filename must not contain a drive prefix")
    if original_filename in {".", ".."}:
        raise FilenameValidationError("Filename must not be a path component")
    if any(
        char in _PATH_SEPARATOR_LOOKALIKES or char in _BIDI_CONTROLS
        for char in original_filename
    ):
        raise FilenameValidationError("Filename contains unsafe directional characters")
    if any(unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"} for char in original_filename):
        raise FilenameValidationError("Filename contains control characters")

    try:
        encoded_length = len(original_filename.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise FilenameValidationError("Filename contains invalid Unicode") from exc
    if encoded_length > MAX_DISPLAY_FILENAME_BYTES:
        raise FilenameValidationError("Filename is too long")

    return original_filename


class PDFContentValidator:
    """Incrementally validate PDF metadata, signature, and content length."""

    def __init__(
        self,
        original_filename: str,
        declared_media_type: str | None,
        *,
        max_size_bytes: int = DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
    ) -> None:
        validate_display_filename(original_filename)
        if max_size_bytes <= 0:
            raise ValueError("Maximum document size must be positive")

        extension = original_filename.rpartition(".")[2].casefold()
        if extension != "pdf":
            raise PDFValidationError("Only PDF documents are supported")

        if not isinstance(declared_media_type, str):
            raise PDFValidationError("Declared media type must be application/pdf")
        media_type = declared_media_type.partition(";")[0].strip().casefold()
        if media_type != PDF_MEDIA_TYPE:
            raise PDFValidationError("Declared media type must be application/pdf")

        self._max_size_bytes = max_size_bytes
        self._total_size = 0
        self._signature_prefix = bytearray()
        self._finished = False

    def feed(self, chunk: bytes) -> None:
        """Validate and account for one bounded content chunk."""
        if self._finished:
            raise PDFValidationError("PDF validation has already finished")
        if not isinstance(chunk, bytes):
            raise PDFValidationError("Document content must be supplied as byte chunks")
        self._total_size += len(chunk)
        if self._total_size > self._max_size_bytes:
            raise PDFSizeLimitError("Document exceeds the maximum permitted size")
        needed = len(PDF_SIGNATURE) - len(self._signature_prefix)
        if needed > 0:
            self._signature_prefix.extend(chunk[:needed])

    def finish(self) -> int:
        """Finalize validation and return the exact byte count."""
        if self._finished:
            raise PDFValidationError("PDF validation has already finished")
        self._finished = True
        if self._total_size == 0:
            raise PDFValidationError("Document must not be empty")
        if not bytes(self._signature_prefix).startswith(PDF_SIGNATURE):
            raise PDFValidationError("Document does not have a valid PDF signature")
        return self._total_size


def validate_pdf_content(
    original_filename: str,
    declared_media_type: str | None,
    chunks: Iterable[bytes],
    *,
    max_size_bytes: int = DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
) -> int:
    """Validate a PDF filename, declared type, signature, and streamed size.

    Only a short signature prefix and byte count are retained. A matching
    signature is preliminary; callers must also invoke
    :func:`validate_pdf_structure` on the bounded seekable stream. Neither
    check establishes that PDF content is safe or free of malware.
    """
    validator = PDFContentValidator(
        original_filename,
        declared_media_type,
        max_size_bytes=max_size_bytes,
    )
    for chunk in chunks:
        validator.feed(chunk)
    return validator.finish()
