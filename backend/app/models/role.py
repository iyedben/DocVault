"""The application's fixed role records."""

from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (
        CheckConstraint("name IN ('user', 'administrator')", name="ck_roles_allowed_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    users: Mapped[list["User"]] = relationship(back_populates="role")
