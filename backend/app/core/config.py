"""Environment-backed application configuration."""

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DOCUMENT_STORAGE_ROOT = Path("/var/lib/docvault/documents")
DEFAULT_MAX_DOCUMENT_SIZE_BYTES = 10 * 1024 * 1024
DOCUMENT_MULTIPART_OVERHEAD_BYTES = 64 * 1024
DEFAULT_MAX_REQUEST_BODY_SIZE_BYTES = (
    DEFAULT_MAX_DOCUMENT_SIZE_BYTES + DOCUMENT_MULTIPART_OVERHEAD_BYTES
)


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    host: str
    port: int
    name: str
    user: str
    password: str

    @classmethod
    def from_environment(cls) -> "DatabaseSettings":
        """Read the application database settings from the process environment."""
        return cls(
            host=os.getenv("DATABASE_HOST", "postgres"),
            port=int(os.getenv("DATABASE_PORT", "5432")),
            name=os.getenv("DATABASE_NAME", "docvault"),
            user=os.getenv("DATABASE_USER", "docvault_app"),
            password=os.getenv("DATABASE_PASSWORD", ""),
        )


@dataclass(frozen=True, slots=True)
class AuthSettings:
    cookie_secure: bool
    session_ttl_seconds: int
    idle_timeout_seconds: int
    canonical_origin: str = "http://127.0.0.1:8000"
    allowed_origins: tuple[str, ...] = (
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://testserver",
    )

    @classmethod
    def from_environment(cls) -> "AuthSettings":
        secure_value = os.getenv("AUTH_COOKIE_SECURE", "false").strip().lower()
        if secure_value not in {"true", "false", "1", "0", "yes", "no"}:
            raise ValueError("AUTH_COOKIE_SECURE must be true or false")
        session_ttl = int(os.getenv("AUTH_SESSION_TTL_SECONDS", "28800"))
        idle_timeout = int(os.getenv("AUTH_IDLE_TIMEOUT_SECONDS", "1800"))
        if session_ttl <= 0 or idle_timeout <= 0 or idle_timeout > session_ttl:
            raise ValueError("Authentication session timeouts are invalid")
        canonical_origin = os.getenv("APP_CANONICAL_ORIGIN", "http://127.0.0.1:8000").strip().rstrip("/")
        allowed_origins_env = os.getenv("APP_ALLOWED_ORIGINS")
        if allowed_origins_env:
            allowed_origins = tuple(o.strip().rstrip("/") for o in allowed_origins_env.split(",") if o.strip())
        else:
            allowed_origins = (canonical_origin, "http://localhost:8000", "http://testserver")

        return cls(
            cookie_secure=secure_value in {"true", "1", "yes"},
            session_ttl_seconds=session_ttl,
            idle_timeout_seconds=idle_timeout,
            canonical_origin=canonical_origin,
            allowed_origins=allowed_origins,
        )


@dataclass(frozen=True, slots=True)
class DocumentSettings:
    """Validated settings for private document handling."""

    storage_root: Path
    max_document_size_bytes: int
    max_request_body_size_bytes: int

    @classmethod
    def from_environment(cls) -> "DocumentSettings":
        """Read document limits and storage location from the environment."""
        storage_root_value = os.getenv(
            "DOCUMENT_STORAGE_ROOT", str(DEFAULT_DOCUMENT_STORAGE_ROOT)
        )
        storage_root = Path(storage_root_value)
        if not storage_root_value.strip() or not storage_root.is_absolute():
            raise ValueError("DOCUMENT_STORAGE_ROOT must be an absolute path")

        max_document_size = int(
            os.getenv("DOCUMENT_MAX_SIZE_BYTES", str(DEFAULT_MAX_DOCUMENT_SIZE_BYTES))
        )
        max_request_body_size = int(
            os.getenv(
                "DOCUMENT_MAX_REQUEST_BODY_BYTES",
                str(DEFAULT_MAX_REQUEST_BODY_SIZE_BYTES),
            )
        )
        if max_document_size <= 0 or max_request_body_size <= 0:
            raise ValueError("Document size limits must be positive")
        if max_document_size > DEFAULT_MAX_DOCUMENT_SIZE_BYTES:
            raise ValueError("DOCUMENT_MAX_SIZE_BYTES exceeds the approved maximum")
        if max_request_body_size != max_document_size + DOCUMENT_MULTIPART_OVERHEAD_BYTES:
            raise ValueError(
                "DOCUMENT_MAX_REQUEST_BODY_BYTES must equal the document limit "
                "plus multipart overhead"
            )

        return cls(
            storage_root=storage_root,
            max_document_size_bytes=max_document_size,
            max_request_body_size_bytes=max_request_body_size,
        )
