"""Descriptor-relative storage for private document files.

The configured root is opened once and pinned by a directory file descriptor.
Every file operation is relative to that descriptor and accepts only canonical
UUID storage keys. Client filenames are deliberately absent from this module.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

from app.core.config import DEFAULT_MAX_DOCUMENT_SIZE_BYTES

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_REQUIRED_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_REQUIRED_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_REQUIRED_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class StorageError(Exception):
    """Base class for safe, path-free storage errors."""


class StorageConfigurationError(StorageError):
    """The configured storage root is unavailable or insecure."""


class InvalidStorageKey(StorageError, ValueError):
    """A storage key is not a canonical UUID."""


class StorageKeyConflict(StorageError):
    """A final storage key already exists."""


class StoredFileNotFound(StorageError):
    """No stored file exists for the requested key."""


class StorageIntegrityError(StorageError):
    """A storage entry is not a regular file or failed integrity checks."""


class StorageLimitExceeded(StorageError):
    """A staged document exceeds the configured byte limit."""


class EmptyDocumentError(StorageError):
    """An empty document cannot be staged."""


@dataclass(slots=True)
class _StagedFile:
    """An unforgeable-to-callers handle for one in-progress staged file."""

    _owner: object
    _name: str
    _fd: int | None
    _size: int = 0
    _finished: bool = False


class PrivateDocumentStorage:
    """Private, bounded file storage rooted at a pinned directory descriptor."""

    def __init__(
        self,
        root: Path,
        *,
        max_size_bytes: int = DEFAULT_MAX_DOCUMENT_SIZE_BYTES,
        owner_uid: int | None = None,
        owner_gid: int | None = None,
    ) -> None:
        if not root.is_absolute():
            raise StorageConfigurationError("Storage root must be an absolute path")
        if max_size_bytes <= 0:
            raise StorageConfigurationError("Maximum document size must be positive")
        self._require_platform_support()
        self._max_size_bytes = max_size_bytes
        self._owner_uid = os.geteuid() if owner_uid is None else owner_uid
        self._owner_gid = os.getegid() if owner_gid is None else owner_gid
        self._owner_token = object()
        self._closed = False

        try:
            os.mkdir(root, _DIRECTORY_MODE)
        except FileExistsError:
            pass
        except OSError:
            raise StorageConfigurationError(
                "Storage root could not be initialized"
            ) from None

        flags = os.O_RDONLY | _REQUIRED_DIRECTORY | _REQUIRED_NOFOLLOW | _REQUIRED_CLOEXEC
        try:
            self._root_fd = os.open(root, flags)
        except OSError:
            raise StorageConfigurationError(
                "Storage root could not be safely opened"
            ) from None

        try:
            self._validate_root_fd()
        except BaseException:
            os.close(self._root_fd)
            self._closed = True
            raise

    @staticmethod
    def _require_platform_support() -> None:
        required_dir_fd = (os.open, os.stat, os.link, os.unlink)
        if (
            not _REQUIRED_NOFOLLOW
            or not _REQUIRED_DIRECTORY
            or not _REQUIRED_CLOEXEC
            or any(operation not in os.supports_dir_fd for operation in required_dir_fd)
            or os.stat not in os.supports_follow_symlinks
            or os.link not in os.supports_follow_symlinks
        ):
            raise StorageConfigurationError(
                "Platform lacks required descriptor-relative filesystem operations"
            )

    def _validate_root_fd(self) -> None:
        if self._closed:
            raise StorageConfigurationError("Storage instance is closed")
        try:
            root_stat = os.fstat(self._root_fd)
        except OSError:
            raise StorageConfigurationError(
                "Storage root descriptor is invalid"
            ) from None
        if not stat.S_ISDIR(root_stat.st_mode):
            raise StorageConfigurationError("Storage root is not a directory")
        if stat.S_IMODE(root_stat.st_mode) != _DIRECTORY_MODE:
            raise StorageConfigurationError("Storage root permissions must be 0700")
        if root_stat.st_uid != self._owner_uid or root_stat.st_gid != self._owner_gid:
            raise StorageConfigurationError(
                "Storage root must belong to the configured API identity"
            )

    @staticmethod
    def _storage_key_name(storage_key: uuid.UUID | str) -> str:
        if isinstance(storage_key, uuid.UUID):
            return str(storage_key)
        if not isinstance(storage_key, str):
            raise InvalidStorageKey("Storage key must be a UUID")
        try:
            parsed_key = uuid.UUID(storage_key)
        except (ValueError, AttributeError):
            raise InvalidStorageKey("Storage key must be a canonical UUID") from None
        canonical_key = str(parsed_key)
        if storage_key != canonical_key:
            raise InvalidStorageKey("Storage key must be a canonical UUID")
        return canonical_key

    def _validate_staged(self, staged: _StagedFile) -> None:
        if not isinstance(staged, _StagedFile) or staged._owner is not self._owner_token:
            raise StorageError("Staged file does not belong to this storage instance")
        if staged._finished:
            raise StorageError("Staged file has already been finalized")

    def create_staged_file(self) -> _StagedFile:
        """Create a unique mode-0600 staging file beneath the pinned root."""
        self._validate_root_fd()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _REQUIRED_NOFOLLOW | _REQUIRED_CLOEXEC
        for _attempt in range(5):
            staged_name = f".stage-{secrets.token_hex(16)}"
            try:
                staged_fd = os.open(
                    staged_name,
                    flags,
                    _FILE_MODE,
                    dir_fd=self._root_fd,
                )
            except FileExistsError:
                continue
            except OSError:
                raise StorageError("Could not create a staging file") from None
            return _StagedFile(self._owner_token, staged_name, staged_fd)
        raise StorageError("Could not allocate a unique staging file")

    def write_chunks(self, staged: _StagedFile, chunks: Iterable[bytes]) -> int:
        """Write bounded byte chunks; any failure closes and removes the stage."""
        self._validate_root_fd()
        self._validate_staged(staged)
        if staged._fd is None:
            raise StorageError("Staging file is not open for writing")
        try:
            for chunk in chunks:
                if not isinstance(chunk, bytes):
                    raise StorageError("Document data must be supplied as byte chunks")
                if not chunk:
                    continue
                if staged._size + len(chunk) > self._max_size_bytes:
                    raise StorageLimitExceeded("Document exceeds the maximum size")
                view = memoryview(chunk)
                while view:
                    written = os.write(staged._fd, view)
                    if written <= 0:
                        raise StorageError("Could not write document data")
                    staged._size += written
                    view = view[written:]
            if staged._size == 0:
                raise EmptyDocumentError("Document must not be empty")
            return staged._size
        except OSError:
            self.delete_staged_file(staged)
            raise StorageError("Could not write document data") from None
        except BaseException:
            self.delete_staged_file(staged)
            raise

    def promote(
        self, staged: _StagedFile, storage_key: uuid.UUID | str
    ) -> uuid.UUID:
        """Publish a stage under a UUID without replacing an existing entry."""
        self._validate_root_fd()
        self._validate_staged(staged)
        if staged._size <= 0 or staged._fd is None:
            self.delete_staged_file(staged)
            raise EmptyDocumentError("Document must not be empty")

        final_link_created = False
        final_name: str | None = None
        try:
            final_name = self._storage_key_name(storage_key)
            staged_stat = os.fstat(staged._fd)
            if not stat.S_ISREG(staged_stat.st_mode):
                raise StorageIntegrityError("Staging entry is not a regular file")
            os.fchmod(staged._fd, _FILE_MODE)
            os.fsync(staged._fd)
            os.link(
                staged._name,
                final_name,
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._root_fd,
                follow_symlinks=False,
            )
            final_link_created = True
            final_stat = os.stat(
                final_name, dir_fd=self._root_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(final_stat.st_mode)
                or final_stat.st_dev != staged_stat.st_dev
                or final_stat.st_ino != staged_stat.st_ino
            ):
                raise StorageIntegrityError("Promoted file failed integrity checks")
            os.unlink(staged._name, dir_fd=self._root_fd)
            os.close(staged._fd)
            staged._fd = None
            staged._finished = True
            return uuid.UUID(final_name)
        except FileExistsError:
            self._cleanup_failed_promotion(staged, final_name, final_link_created)
            raise StorageKeyConflict("Storage key already exists") from None
        except BaseException as exc:
            self._cleanup_failed_promotion(staged, final_name, final_link_created)
            if isinstance(exc, StorageError):
                raise
            if isinstance(exc, OSError):
                raise StorageError("Could not promote staged document") from None
            raise

    def _cleanup_failed_promotion(
        self, staged: _StagedFile, final_name: str | None, final_link_created: bool
    ) -> None:
        if final_link_created and final_name is not None:
            try:
                os.unlink(final_name, dir_fd=self._root_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        self.delete_staged_file(staged)

    def open_file(self, storage_key: uuid.UUID | str) -> BinaryIO:
        """Open a stored regular file without following symlinks."""
        self._validate_root_fd()
        name = self._storage_key_name(storage_key)
        flags = os.O_RDONLY | _REQUIRED_NOFOLLOW | _REQUIRED_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        file_fd: int | None = None
        try:
            file_fd = os.open(name, flags, dir_fd=self._root_fd)
        except FileNotFoundError:
            raise StoredFileNotFound("Stored document does not exist") from None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise StorageIntegrityError("Stored entry must not be a symlink") from None
            raise StorageError("Could not safely open stored document") from None

        try:
            file_stat = os.fstat(file_fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise StorageIntegrityError("Stored entry is not a regular file")
            if (
                file_stat.st_uid != self._owner_uid
                or file_stat.st_gid != self._owner_gid
                or stat.S_IMODE(file_stat.st_mode) != _FILE_MODE
            ):
                raise StorageIntegrityError("Stored file ownership or mode is invalid")
            if file_stat.st_size <= 0 or file_stat.st_size > self._max_size_bytes:
                raise StorageIntegrityError("Stored file size is outside permitted bounds")
            file_object = os.fdopen(file_fd, "rb", closefd=True)
            file_fd = None
            return file_object
        except BaseException:
            if file_fd is not None:
                os.close(file_fd)
            raise

    def delete_staged_file(self, staged: _StagedFile) -> None:
        """Close and remove a staging entry, safely tolerating prior removal."""
        self._validate_staged(staged)
        close_failed = False
        if staged._fd is not None:
            try:
                os.close(staged._fd)
            except OSError:
                close_failed = True
            finally:
                staged._fd = None
        try:
            os.unlink(staged._name, dir_fd=self._root_fd)
        except FileNotFoundError:
            pass
        except OSError:
            staged._finished = True
            raise StorageError("Could not remove staging file") from None
        staged._finished = True
        if close_failed:
            raise StorageError("Could not close staging descriptor")

    def delete_file(self, storage_key: uuid.UUID | str) -> bool:
        """Delete a stored regular file; return False when it is already absent."""
        self._validate_root_fd()
        name = self._storage_key_name(storage_key)
        try:
            entry_stat = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            raise StorageError("Could not inspect stored document") from None
        if not stat.S_ISREG(entry_stat.st_mode):
            raise StorageIntegrityError("Stored entry is not a regular file")
        try:
            os.unlink(name, dir_fd=self._root_fd)
        except FileNotFoundError:
            return False
        except OSError:
            raise StorageError("Could not delete stored document") from None
        return True

    def close(self) -> None:
        """Close the pinned root descriptor; safe to call more than once."""
        if not self._closed:
            os.close(self._root_fd)
            self._closed = True

    def __enter__(self) -> Self:
        self._validate_root_fd()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
