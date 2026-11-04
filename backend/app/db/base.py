"""SQLAlchemy declarative base for future application models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for models added in a later phase."""
