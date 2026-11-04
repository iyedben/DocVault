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
