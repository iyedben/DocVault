"""Argon2id password hashing and input policy."""

from __future__ import annotations

import secrets
import threading

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError

PASSWORD_HASHER = PasswordHasher(type=Type.ID)
_ARGON2_SLOTS = threading.BoundedSemaphore(value=2)
_dummy_hash_value: str | None = None
_dummy_hash_lock = threading.Lock()


class PasswordPolicyError(ValueError):
    """Raised when a newly supplied password does not meet policy."""


def validate_password(password: str) -> None:
    if not 12 <= len(password) <= 128:
        raise PasswordPolicyError("Password must be between 12 and 128 characters")
    if any(not character.isprintable() for character in password):
        raise PasswordPolicyError("Password contains unsupported characters")
    categories = sum(
        (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() for character in password),
        )
    )
    if categories < 3:
        raise PasswordPolicyError("Password must use at least three character categories")


def hash_password(password: str) -> str:
    validate_password(password)
    with _ARGON2_SLOTS:
        return PASSWORD_HASHER.hash(password)


def _dummy_hash() -> str:
    global _dummy_hash_value
    if _dummy_hash_value is None:
        with _dummy_hash_lock:
            if _dummy_hash_value is None:
                with _ARGON2_SLOTS:
                    _dummy_hash_value = PASSWORD_HASHER.hash(secrets.token_urlsafe(32))
    return _dummy_hash_value


def verify_password(password: str, encoded_hash: str | None) -> bool:
    candidate_hash = encoded_hash if encoded_hash is not None else _dummy_hash()
    try:
        with _ARGON2_SLOTS:
            valid = PASSWORD_HASHER.verify(candidate_hash, password)
    except VerificationError:
        return False
    return bool(valid) and encoded_hash is not None


def password_hash_needs_rehash(encoded_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.check_needs_rehash(encoded_hash)
    except VerificationError:
        return False
