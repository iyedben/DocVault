"""Pure filename and PDF validation for future document upload handling."""

import ntpath
import unicodedata
from collections.abc import Iterable

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


def validate_pdf_content(
    original_filename: str,
    declared_media_type: str,
    chunks: Iterable[bytes],
    *,
    max_size_bytes: int = DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
) -> int:
    """Validate a PDF filename, declared type, signature, and streamed size.

    The function retains only the first few signature bytes and a byte count;
    callers supply content in bounded chunks. The returned value is the total
    validated byte count. A matching signature is only a format check and does
    not establish that PDF content is harmless.
    """
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

    total_size = 0
    signature_prefix = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise PDFValidationError("Document content must be supplied as byte chunks")
        total_size += len(chunk)
        if total_size > max_size_bytes:
            raise PDFValidationError("Document exceeds the maximum permitted size")
        needed = len(PDF_SIGNATURE) - len(signature_prefix)
        if needed > 0:
            signature_prefix.extend(chunk[:needed])

    if total_size == 0:
        raise PDFValidationError("Document must not be empty")
    if not bytes(signature_prefix).startswith(PDF_SIGNATURE):
        raise PDFValidationError("Document does not have a valid PDF signature")
    return total_size
