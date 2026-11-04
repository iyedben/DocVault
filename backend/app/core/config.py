"""Environment-backed application configuration."""

import os
from dataclasses import dataclass


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

    @classmethod
    def from_environment(cls) -> "AuthSettings":
        secure_value = os.getenv("AUTH_COOKIE_SECURE", "false").strip().lower()
        if secure_value not in {"true", "false", "1", "0", "yes", "no"}:
            raise ValueError("AUTH_COOKIE_SECURE must be true or false")
        session_ttl = int(os.getenv("AUTH_SESSION_TTL_SECONDS", "28800"))
        idle_timeout = int(os.getenv("AUTH_IDLE_TIMEOUT_SECONDS", "1800"))
        if session_ttl <= 0 or idle_timeout <= 0 or idle_timeout > session_ttl:
            raise ValueError("Authentication session timeouts are invalid")
        return cls(
            cookie_secure=secure_value in {"true", "1", "yes"},
            session_ttl_seconds=session_ttl,
            idle_timeout_seconds=idle_timeout,
        )
