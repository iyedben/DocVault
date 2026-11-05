"""Isolated tests for private descriptor-relative document storage."""

import os
import stat
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from app.storage import (
    EmptyDocumentError,
    InvalidStorageKey,
    PrivateDocumentStorage,
    StorageConfigurationError,
    StorageIntegrityError,
    StorageKeyConflict,
    StorageLimitExceeded,
    StoredFileNotFound,
)

MAX_TEST_SIZE = 64


@pytest.fixture
def storage(tmp_path: Path) -> Iterator[PrivateDocumentStorage]:
    root = tmp_path / "private-documents"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    instance = PrivateDocumentStorage(root, max_size_bytes=MAX_TEST_SIZE)
    try:
        yield instance
    finally:
        instance.close()


def staged_names(root: Path) -> set[str]:
    return {entry.name for entry in root.iterdir() if entry.name.startswith(".stage-")}


def test_storage_initializes_root_with_restrictive_permissions(tmp_path: Path) -> None:
    root = tmp_path / "new-private-root"

    with PrivateDocumentStorage(root, max_size_bytes=MAX_TEST_SIZE) as store:
        root_stat = os.fstat(store._root_fd)
        assert stat.S_ISDIR(root_stat.st_mode)
        assert stat.S_IMODE(root_stat.st_mode) == 0o700
        assert root_stat.st_uid == os.geteuid()
        assert root_stat.st_gid == os.getegid()


def test_storage_rejects_insecure_root_mode(tmp_path: Path) -> None:
    root = tmp_path / "too-open"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o750)

    with pytest.raises(StorageConfigurationError, match="permissions"):
        PrivateDocumentStorage(root, max_size_bytes=MAX_TEST_SIZE)


def test_storage_rejects_wrong_root_owner(tmp_path: Path) -> None:
    root = tmp_path / "wrong-owner"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)

    with pytest.raises(StorageConfigurationError, match="API identity"):
        PrivateDocumentStorage(
            root,
            max_size_bytes=MAX_TEST_SIZE,
            owner_uid=os.geteuid() + 1,
        )


def test_storage_rejects_symlink_as_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    os.chmod(target, 0o700)
    root_link = tmp_path / "root-link"
    root_link.symlink_to(target, target_is_directory=True)

    with pytest.raises(StorageConfigurationError, match="safely opened"):
        PrivateDocumentStorage(root_link, max_size_bytes=MAX_TEST_SIZE)


def test_stage_write_promote_read_and_delete(storage: PrivateDocumentStorage) -> None:
    staged = storage.create_staged_file()
    assert storage.write_chunks(staged, [b"%PDF-", b"sample bytes"]) == 17
    storage_key = uuid.uuid4()

    assert storage.promote(staged, storage_key) == storage_key
    with storage.open_file(storage_key) as document:
        assert document.read() == b"%PDF-sample bytes"
        assert stat.S_IMODE(os.fstat(document.fileno()).st_mode) == 0o600
    assert storage.delete_file(storage_key) is True
    assert storage.delete_file(storage_key) is False
    with pytest.raises(StoredFileNotFound):
        storage.open_file(storage_key)


def test_empty_stage_is_rejected_and_removed(
    storage: PrivateDocumentStorage, tmp_path: Path
) -> None:
    staged = storage.create_staged_file()

    with pytest.raises(EmptyDocumentError):
        storage.write_chunks(staged, [])

    assert staged._fd is None
    assert staged_names(tmp_path / "private-documents") == set()


def test_empty_chunks_do_not_make_a_nonempty_document(
    storage: PrivateDocumentStorage, tmp_path: Path
) -> None:
    staged = storage.create_staged_file()

    with pytest.raises(EmptyDocumentError):
        storage.write_chunks(staged, [b"", b""])

    assert staged._fd is None
    assert staged_names(tmp_path / "private-documents") == set()


def test_oversized_write_is_rejected_and_removed(
    storage: PrivateDocumentStorage, tmp_path: Path
) -> None:
    staged = storage.create_staged_file()

    with pytest.raises(StorageLimitExceeded):
        storage.write_chunks(staged, [b"x" * MAX_TEST_SIZE, b"y"])

    assert staged._fd is None
    assert staged_names(tmp_path / "private-documents") == set()


def test_duplicate_storage_key_does_not_replace_existing_file(
    storage: PrivateDocumentStorage, tmp_path: Path
) -> None:
    storage_key = uuid.uuid4()
    first = storage.create_staged_file()
    storage.write_chunks(first, [b"original"])
    storage.promote(first, storage_key)

    second = storage.create_staged_file()
    second_fd = second._fd
    storage.write_chunks(second, [b"replacement"])
    with pytest.raises(StorageKeyConflict):
        storage.promote(second, storage_key)

    assert second._fd is None
    assert second_fd is not None
    with pytest.raises(OSError):
        os.fstat(second_fd)
    with storage.open_file(storage_key) as existing:
        assert existing.read() == b"original"
    assert staged_names(tmp_path / "private-documents") == set()


@pytest.mark.parametrize(
    "storage_key",
    [
        "../escape",
        "..\\escape",
        "/absolute/path",
        "C:\\escape",
        "not-a-uuid",
        "{00000000-0000-0000-0000-000000000001}",
        "00000000-0000-0000-0000-00000000000A",
    ],
)
def test_invalid_storage_keys_are_rejected(
    storage: PrivateDocumentStorage, storage_key: str
) -> None:
    with pytest.raises(InvalidStorageKey):
        storage.open_file(storage_key)
    with pytest.raises(InvalidStorageKey):
        storage.delete_file(storage_key)


def test_symlink_entries_are_rejected_without_touching_target(
    storage: PrivateDocumentStorage, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"outside")
    storage_key = uuid.uuid4()
    os.symlink(outside, str(storage_key), dir_fd=storage._root_fd)

    with pytest.raises(StorageIntegrityError, match="symlink"):
        storage.open_file(storage_key)
    with pytest.raises(StorageIntegrityError, match="regular file"):
        storage.delete_file(storage_key)
    assert outside.read_bytes() == b"outside"


def test_nonregular_entries_are_rejected(storage: PrivateDocumentStorage) -> None:
    storage_key = uuid.uuid4()
    os.mkdir(str(storage_key), mode=0o700, dir_fd=storage._root_fd)

    with pytest.raises(StorageIntegrityError, match="regular file"):
        storage.open_file(storage_key)
    with pytest.raises(StorageIntegrityError, match="regular file"):
        storage.delete_file(storage_key)


def test_write_exception_removes_stage_and_closes_descriptor(
    storage: PrivateDocumentStorage, tmp_path: Path
) -> None:
    staged = storage.create_staged_file()
    staged_fd = staged._fd

    def failing_chunks() -> Iterator[bytes]:
        yield b"partial"
        raise RuntimeError("synthetic source failure")

    with pytest.raises(RuntimeError, match="synthetic source failure"):
        storage.write_chunks(staged, failing_chunks())

    assert staged._fd is None
    assert staged_fd is not None
    with pytest.raises(OSError):
        os.fstat(staged_fd)
    assert staged_names(tmp_path / "private-documents") == set()


def test_invalid_promotion_key_cleans_stage(
    storage: PrivateDocumentStorage, tmp_path: Path
) -> None:
    staged = storage.create_staged_file()
    storage.write_chunks(staged, [b"bytes"])

    with pytest.raises(InvalidStorageKey):
        storage.promote(staged, "../escape")

    assert staged._fd is None
    assert staged_names(tmp_path / "private-documents") == set()


def test_open_file_closes_descriptor_if_wrapping_fails(
    storage: PrivateDocumentStorage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged = storage.create_staged_file()
    storage.write_chunks(staged, [b"stored"])
    storage_key = uuid.uuid4()
    storage.promote(staged, storage_key)
    opened_descriptors: list[int] = []

    def fail_fdopen(file_fd: int, *_args: object, **_kwargs: object) -> None:
        opened_descriptors.append(file_fd)
        raise RuntimeError("synthetic fd wrapping failure")

    monkeypatch.setattr("app.storage.filesystem.os.fdopen", fail_fdopen)
    with pytest.raises(RuntimeError, match="fd wrapping failure"):
        storage.open_file(storage_key)

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(opened_descriptors[0])


def test_operations_remain_inside_pinned_root_after_path_replacement(
    storage: PrivateDocumentStorage, tmp_path: Path
) -> None:
    configured_root = tmp_path / "private-documents"
    pinned_root = tmp_path / "renamed-private-root"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    configured_root.rename(pinned_root)
    configured_root.symlink_to(outside, target_is_directory=True)

    staged = storage.create_staged_file()
    storage.write_chunks(staged, [b"confined data"])
    storage_key = uuid.uuid4()
    storage.promote(staged, storage_key)

    assert (pinned_root / str(storage_key)).read_bytes() == b"confined data"
    assert list(outside.iterdir()) == []
