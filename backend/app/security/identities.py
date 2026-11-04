"""Canonical username validation."""

import re
import unicodedata

_USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")


def normalize_username(username: str) -> str:
    return unicodedata.normalize("NFKC", username).strip().casefold()


def valid_username(username: str) -> bool:
    return _USERNAME_PATTERN.fullmatch(username) is not None
