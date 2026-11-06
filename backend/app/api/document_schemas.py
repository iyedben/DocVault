"""Safe document API representations without storage implementation details."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel


class DocumentResponse(BaseModel):
    id: UUID
    display_filename: str
    media_type: Literal["application/pdf"]
    file_size: int
    created_at: datetime
    access: Literal["owner", "shared"]


class DocumentShareResponse(BaseModel):
    user_id: UUID
    username: str
    created_at: datetime
