"""Tests for Phase 4 document configuration and pure input validation."""

from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest
from app.core.config import (
    DEFAULT_DOCUMENT_STORAGE_ROOT,
    DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
    DEFAULT_MAX_REQUEST_BODY_SIZE_BYTES,
    DOCUMENT_MULTIPART_OVERHEAD_BYTES,
    DocumentSettings,
)
from app.security.document_validation import (
    MAX_DISPLAY_FILENAME_BYTES,
    FilenameValidationError,
    PDFValidationError,
    validate_display_filename,
    validate_pdf_content,
    validate_pdf_structure,
)
from pypdf import PdfReader

FIXTURES = Path(__file__).parent / "fixtures"
VALID_MINIMAL_PDF = (FIXTURES / "minimal_valid.pdf").read_bytes()
SUSPICIOUS_VALID_PDF = (FIXTURES / "valid_with_embedded_javascript.pdf").read_bytes()
VALID_PDF_PREFIX = VALID_MINIMAL_PDF


def chunks_of(content: bytes, chunk_size: int = 64 * 1024) -> Iterator[bytes]:
    for offset in range(0, len(content), chunk_size):
        yield content[offset : offset + chunk_size]


def validate(content: bytes, *, filename: str = "sample.pdf", media_type: str = "application/pdf", max_size: int = 1024) -> int:
    return validate_pdf_content(
        filename,
        media_type,
        chunks_of(content),
        max_size_bytes=max_size,
    )


def test_document_settings_use_secure_defaults(monkeypatch) -> None:
    monkeypatch.delenv("DOCUMENT_STORAGE_ROOT", raising=False)
    monkeypatch.delenv("DOCUMENT_MAX_SIZE_BYTES", raising=False)
    monkeypatch.delenv("DOCUMENT_MAX_REQUEST_BODY_BYTES", raising=False)
    settings = DocumentSettings.from_environment()

    assert settings.storage_root == DEFAULT_DOCUMENT_STORAGE_ROOT
    assert settings.storage_root.is_absolute()
    assert settings.max_document_size_bytes == DEFAULT_MAX_DOCUMENT_SIZE_BYTES
    assert settings.max_request_body_size_bytes == DEFAULT_MAX_REQUEST_BODY_SIZE_BYTES
    assert settings.max_request_body_size_bytes == (
        settings.max_document_size_bytes + DOCUMENT_MULTIPART_OVERHEAD_BYTES
    )


def test_document_settings_accept_consistent_environment_values(monkeypatch) -> None:
    monkeypatch.setenv("DOCUMENT_STORAGE_ROOT", "/private/documents")
    monkeypatch.setenv("DOCUMENT_MAX_SIZE_BYTES", "2048")
    monkeypatch.setenv("DOCUMENT_MAX_REQUEST_BODY_BYTES", str(2048 + DOCUMENT_MULTIPART_OVERHEAD_BYTES))

    settings = DocumentSettings.from_environment()

    assert settings.storage_root == Path("/private/documents")
    assert settings.max_document_size_bytes == 2048
    assert settings.max_request_body_size_bytes == 2048 + DOCUMENT_MULTIPART_OVERHEAD_BYTES


def test_document_settings_reject_request_limit_larger_than_configured_allowance(
    monkeypatch,
) -> None:
    monkeypatch.setenv("DOCUMENT_MAX_SIZE_BYTES", str(DEFAULT_MAX_DOCUMENT_SIZE_BYTES))
    monkeypatch.setenv(
        "DOCUMENT_MAX_REQUEST_BODY_BYTES",
        str(DEFAULT_MAX_REQUEST_BODY_SIZE_BYTES + 1),
    )

    with pytest.raises(ValueError, match="must equal"):
        DocumentSettings.from_environment()


def test_document_settings_reject_request_limit_smaller_than_configured_allowance(
    monkeypatch,
) -> None:
    monkeypatch.setenv("DOCUMENT_MAX_SIZE_BYTES", str(DEFAULT_MAX_DOCUMENT_SIZE_BYTES))
    monkeypatch.setenv(
        "DOCUMENT_MAX_REQUEST_BODY_BYTES",
        str(DEFAULT_MAX_REQUEST_BODY_SIZE_BYTES - 1),
    )

    with pytest.raises(ValueError, match="must equal"):
        DocumentSettings.from_environment()


def test_document_settings_reject_document_limit_above_approved_maximum(
    monkeypatch,
) -> None:
    larger_document_limit = DEFAULT_MAX_DOCUMENT_SIZE_BYTES + 1
    monkeypatch.setenv("DOCUMENT_MAX_SIZE_BYTES", str(larger_document_limit))
    monkeypatch.setenv(
        "DOCUMENT_MAX_REQUEST_BODY_BYTES",
        str(larger_document_limit + DOCUMENT_MULTIPART_OVERHEAD_BYTES),
    )

    with pytest.raises(ValueError, match="exceeds the approved maximum"):
        DocumentSettings.from_environment()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("DOCUMENT_STORAGE_ROOT", ""),
        ("DOCUMENT_STORAGE_ROOT", "relative/documents"),
        ("DOCUMENT_MAX_SIZE_BYTES", "0"),
        ("DOCUMENT_MAX_SIZE_BYTES", "-1"),
        ("DOCUMENT_MAX_REQUEST_BODY_BYTES", "0"),
        ("DOCUMENT_MAX_REQUEST_BODY_BYTES", str(DEFAULT_MAX_DOCUMENT_SIZE_BYTES)),
    ],
)
def test_document_settings_reject_invalid_values(monkeypatch, name: str, value: str) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError):
        DocumentSettings.from_environment()


def test_valid_pdf_is_accepted_in_chunks() -> None:
    content = VALID_PDF_PREFIX + (b"x" * 4096)

    assert validate(content, max_size=len(content)) == len(content)


def test_valid_minimal_pdf_passes_structural_validation() -> None:
    validate_pdf_structure(BytesIO(VALID_MINIMAL_PDF))


def test_pdf_with_embedded_javascript_passes_structure_check_without_malware_claim() -> None:
    # Structural parsing does not execute or classify embedded PDF actions.
    reader = PdfReader(BytesIO(SUSPICIOUS_VALID_PDF), strict=True)
    try:
        action = reader.trailer["/Root"]["/OpenAction"]
        assert action["/S"] == "/JavaScript"
    finally:
        reader.close()
    validate_pdf_structure(BytesIO(SUSPICIOUS_VALID_PDF))


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-1.4\nThis is not a PDF structure.\n%%EOF\n",
        VALID_MINIMAL_PDF[:-24],
        b"%PDX-1.4\n" + VALID_MINIMAL_PDF[len(b"%PDF-1.4\n"):],
        b"",
    ],
    ids=["invalid-structure", "truncated", "incorrect-header", "empty"],
)
def test_structural_validation_rejects_invalid_or_truncated_pdf(content: bytes) -> None:
    with pytest.raises(PDFValidationError):
        validate_pdf_structure(BytesIO(content))


def test_pdf_size_check_rejects_oversized_content_before_parsing() -> None:
    content = VALID_MINIMAL_PDF + b"x" * (DEFAULT_MAX_DOCUMENT_SIZE_BYTES + 1)
    with pytest.raises(PDFValidationError, match="maximum permitted size"):
        validate_pdf_content(
            "sample.pdf",
            "application/pdf",
            chunks_of(content),
            max_size_bytes=DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
        )


def test_pdf_validation_rejects_empty_content() -> None:
    with pytest.raises(PDFValidationError, match="must not be empty"):
        validate(b"")


def test_pdf_validation_rejects_incorrect_extension() -> None:
    with pytest.raises(PDFValidationError, match="Only PDF"):
        validate(VALID_PDF_PREFIX, filename="sample.txt")


def test_pdf_validation_rejects_mismatched_declared_media_type() -> None:
    with pytest.raises(PDFValidationError, match="media type"):
        validate(VALID_PDF_PREFIX, media_type="image/pdf")


def test_pdf_validation_rejects_missing_declared_media_type() -> None:
    with pytest.raises(PDFValidationError, match="media type"):
        validate_pdf_content(
            "sample.pdf", None, [VALID_PDF_PREFIX], max_size_bytes=1024  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("content", [b"not a PDF", b"", b"%PDX-1.7"])
def test_pdf_validation_rejects_invalid_or_missing_signature(content: bytes) -> None:
    with pytest.raises(PDFValidationError):
        validate_pdf_content(
            "sample.pdf", "application/pdf", chunks_of(content), max_size_bytes=1024
        )


def test_pdf_validation_accepts_size_exactly_at_limit() -> None:
    content = VALID_PDF_PREFIX + b"x" * (
        DEFAULT_MAX_DOCUMENT_SIZE_BYTES - len(VALID_PDF_PREFIX)
    )

    assert validate_pdf_content(
        "sample.pdf",
        "application/pdf",
        chunks_of(content),
        max_size_bytes=DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
    ) == DEFAULT_MAX_DOCUMENT_SIZE_BYTES


def test_pdf_validation_rejects_size_one_byte_over_limit_without_draining_source() -> None:
    content = VALID_PDF_PREFIX + b"x" * (
        DEFAULT_MAX_DOCUMENT_SIZE_BYTES + 1 - len(VALID_PDF_PREFIX)
    )
    consumed: list[bytes] = []

    def source() -> Iterator[bytes]:
        for chunk in chunks_of(content, chunk_size=1024 * 1024):
            consumed.append(chunk)
            yield chunk
        raise AssertionError("Validation should stop once the size limit is exceeded")

    with pytest.raises(PDFValidationError, match="maximum permitted size"):
        validate_pdf_content(
            "sample.pdf",
            "application/pdf",
            source(),
            max_size_bytes=DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
        )

    assert len(consumed) == 11


def test_pdf_validation_processes_a_chunked_source() -> None:
    content = VALID_PDF_PREFIX + b"x" * 4096
    chunks_seen = 0

    def source() -> Iterator[bytes]:
        nonlocal chunks_seen
        for chunk in chunks_of(content, 128):
            chunks_seen += 1
            yield chunk

    assert validate_pdf_content(
        "sample.pdf", "application/pdf", source(), max_size_bytes=len(content)
    ) == len(content)
    assert chunks_seen > 1


@pytest.mark.parametrize(
    "signature_chunks",
    [
        (b"%", b"PDF-"),
        (b"%P", b"DF-"),
        (b"%", b"P", b"D", b"F", b"-"),
    ],
)
def test_pdf_signature_is_recognized_when_split_across_chunks(
    signature_chunks: tuple[bytes, ...],
) -> None:
    remaining_content = VALID_PDF_PREFIX[len(b"%PDF-") :]
    chunks = [*signature_chunks, remaining_content]
    expected_size = len(VALID_PDF_PREFIX)

    assert validate_pdf_content(
        "sample.pdf",
        "application/pdf",
        chunks,
        max_size_bytes=expected_size,
    ) == expected_size


@pytest.mark.parametrize(
    "filename",
    [
        "../sample.pdf",
        "folder/sample.pdf",
        "..\\sample.pdf",
        "folder\\sample.pdf",
        "/tmp/sample.pdf",
        "C:\\temp\\sample.pdf",
        "C:sample.pdf",
        "..",
        "sample\x00.pdf",
        "sample\r.pdf",
        "sample\n.pdf",
        "sample\x01.pdf",
        "sample\u202e.pdf",
        "sample\uff0f.pdf",
        "",
        "   ",
        "x" * (MAX_DISPLAY_FILENAME_BYTES + 1),
        "x" * 64 + "😀" * 48 + ".pdf",
        "sample\ud800.pdf",
        " sample.pdf",
        "sample.pdf ",
    ],
)
def test_display_filename_rejects_unsafe_values(filename: str) -> None:
    with pytest.raises(FilenameValidationError):
        validate_display_filename(filename)


@pytest.mark.parametrize("filename", ["report.pdf", "résumé.pdf", "e\u0301.pdf", "📄.pdf"])
def test_display_filename_preserves_safe_unicode(filename: str) -> None:
    assert validate_display_filename(filename) == filename


def test_pdf_validation_accepts_media_type_parameters_case_insensitively() -> None:
    assert validate_pdf_content(
        "sample.PDF",
        " Application/PDF; charset=binary",
        [VALID_PDF_PREFIX],
        max_size_bytes=1024,
    ) == len(VALID_PDF_PREFIX)


def test_pdf_validation_rejects_nonpositive_limit() -> None:
    with pytest.raises(ValueError, match="positive"):
        validate_pdf_content("sample.pdf", "application/pdf", [VALID_PDF_PREFIX], max_size_bytes=0)


def test_pdf_validation_rejects_non_byte_chunks() -> None:
    with pytest.raises(PDFValidationError, match="byte chunks"):
        validate_pdf_content("sample.pdf", "application/pdf", ["not bytes"], max_size_bytes=1024)  # type: ignore[list-item]
