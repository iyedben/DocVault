"""Safe request and response schemas for authentication and user administration."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.security.identities import normalize_username, valid_username
from app.security.passwords import PasswordPolicyError, validate_password


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictRequest):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=128)


class CreateUserRequest(StrictRequest):
    username: str = Field(min_length=3, max_length=32)
    password: SecretStr = Field(min_length=12, max_length=128)
    role: Literal["user", "administrator"] = "user"

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        normalized = normalize_username(value)
        if not valid_username(normalized):
            raise ValueError("Username must use 3–32 lowercase letters, digits, dots, underscores or hyphens")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_new_password(cls, value: SecretStr) -> SecretStr:
        try:
            validate_password(value.get_secret_value())
        except PasswordPolicyError as exc:
            raise ValueError(str(exc)) from exc
        return value


class UserStatusRequest(StrictRequest):
    is_active: bool


class UserRoleRequest(StrictRequest):
    role: Literal["user", "administrator"]


class SafeUser(BaseModel):
    id: UUID
    username: str
    role: Literal["user", "administrator"]
    is_active: bool
    created_at: datetime
    updated_at: datetime


class LoginResponse(BaseModel):
    user: SafeUser
    csrf_token: str
