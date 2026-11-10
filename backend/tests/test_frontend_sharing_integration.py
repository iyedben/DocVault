"""Tests for Phase B4 document sharing, user lookup, and access control integration."""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import httpx
import pytest
from app.api.dependencies import get_db
from app.api.routes.documents import get_document_storage
from app.core.config import AuthSettings
from app.db.base import Base
from app.main import app
from app.models import Document, Role, User
from app.security.passwords import hash_password
from app.security.sessions import issue_auth_session
from app.storage import PrivateDocumentStorage
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

VALID_PDF = (Path(__file__).parent / "fixtures" / "minimal_valid.pdf").read_bytes()
TEST_PASSWORD = "StrongPassword#2026-Sharing"


@pytest.fixture
def share_env() -> Generator[
    tuple[
        httpx.AsyncClient,
        sessionmaker[Session],
        User,
        User,
        User,
        User,
        str,
        str,
        str,
        str,
        PrivateDocumentStorage,
    ],
    None,
    None,
]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    temp_dir = TemporaryDirectory()
    storage_root = Path(temp_dir.name)
    storage = PrivateDocumentStorage(storage_root, max_size_bytes=10 * 1024 * 1024)

    settings = AuthSettings(cookie_secure=False, session_ttl_seconds=3600, idle_timeout_seconds=1800)

    with session_factory() as db:
        user_role = Role(name="user")
        db.add(user_role)
        db.flush()

        alice = User(
            username="alice",
            password_hash=hash_password(TEST_PASSWORD),
            role=user_role,
        )
        bob = User(
            username="bob",
            password_hash=hash_password(TEST_PASSWORD),
            role=user_role,
        )
        carol = User(
            username="carol",
            password_hash=hash_password(TEST_PASSWORD),
            role=user_role,
        )
        inactive_user = User(
            username="inactive_dave",
            password_hash=hash_password(TEST_PASSWORD),
            role=user_role,
            is_active=False,
        )
        db.add_all([alice, bob, carol, inactive_user])
        db.flush()

        _, alice_session_token, alice_csrf_token = issue_auth_session(db, alice, settings)
        _, bob_session_token, bob_csrf_token = issue_auth_session(db, bob, settings)
        db.commit()

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    def override_get_storage():
        yield storage

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_document_storage] = override_get_storage

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield (
                client,
                session_factory,
                alice,
                bob,
                carol,
                inactive_user,
                alice_session_token,
                alice_csrf_token,
                bob_session_token,
                bob_csrf_token,
                storage,
            )

    gen = run()
    val = asyncio.run(anext(gen))
    try:
        yield val
    finally:
        try:
            asyncio.run(anext(gen))
        except StopAsyncIteration:
            pass
        app.dependency_overrides.clear()
        storage.close()
        temp_dir.cleanup()
        engine.dispose()


def _create_owned_document(
    session_factory: sessionmaker[Session],
    storage: PrivateDocumentStorage,
    owner: User,
    filename: str = "report.pdf",
) -> Document:
    key = uuid4()
    staged = storage.create_staged_file()
    storage.write_chunks(staged, [VALID_PDF])
    storage.promote(staged, key)

    with session_factory() as db:
        doc = Document(
            owner_id=owner.id,
            display_filename=filename,
            storage_key=key,
            file_size=len(VALID_PDF),
            media_type="application/pdf",
            status="active",
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)
        return doc


def test_anonymous_user_lookup_is_denied(share_env) -> None:
    """Anonymous user cannot access the user lookup endpoint."""
    client, _, _, _, _, _, _, _, _, _, _ = share_env
    res = asyncio.run(client.get("/api/v1/users/lookup?username=alice"))
    assert res.status_code == 401


def test_user_lookup_validation_and_matching(share_env) -> None:
    """User lookup validates query length and returns only active users matching partial name."""
    client, _, _, bob, carol, _, alice_sess, _, _, _, _ = share_env

    # 1. Query shorter than 2 characters is rejected
    res_short = asyncio.run(
        client.get(
            "/api/v1/users/lookup?username=a",
            cookies={"docvault_session": alice_sess},
        )
    )
    assert res_short.status_code == 422

    # 2. Query matching active user 'bob'
    res_bob = asyncio.run(
        client.get(
            "/api/v1/users/lookup?username=bo",
            cookies={"docvault_session": alice_sess},
        )
    )
    assert res_bob.status_code == 200
    results_bob = res_bob.json()
    assert any(u["username"] == "bob" and u["id"] == str(bob.id) for u in results_bob)

    # 3. Query matching active user 'carol'
    res_carol = asyncio.run(
        client.get(
            "/api/v1/users/lookup?username=car",
            cookies={"docvault_session": alice_sess},
        )
    )
    assert res_carol.status_code == 200
    results_carol = res_carol.json()
    assert any(u["username"] == "carol" and u["id"] == str(carol.id) for u in results_carol)

    # 4. Inactive user is never returned in search results
    res_inactive = asyncio.run(
        client.get(
            "/api/v1/users/lookup?username=dave",
            cookies={"docvault_session": alice_sess},
        )
    )
    assert res_inactive.status_code == 200
    results_inactive = res_inactive.json()
    assert not any(u["username"] == "inactive_dave" for u in results_inactive)


def test_anonymous_cannot_access_or_modify_shares(share_env) -> None:
    """Anonymous requests to document share endpoints are rejected with 401."""
    client, session_factory, alice, bob, _, _, _, _, _, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    # GET shares
    res_get = asyncio.run(client.get(f"/api/v1/documents/{doc.id}/shares"))
    assert res_get.status_code == 401

    # PUT share
    res_put = asyncio.run(client.put(f"/api/v1/documents/{doc.id}/shares/{bob.id}"))
    assert res_put.status_code == 401

    # DELETE share
    res_del = asyncio.run(client.delete(f"/api/v1/documents/{doc.id}/shares/{bob.id}"))
    assert res_del.status_code == 401


def test_document_owner_can_list_empty_and_populated_shares(share_env) -> None:
    """Document owner can list shares; initially empty, populated after grant."""
    client, session_factory, alice, bob, _, _, alice_sess, alice_csrf, _, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    # Initially empty
    res_initial = asyncio.run(
        client.get(
            f"/api/v1/documents/{doc.id}/shares",
            cookies={"docvault_session": alice_sess},
        )
    )
    assert res_initial.status_code == 200
    assert res_initial.json() == []

    # Grant share to Bob
    res_grant = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res_grant.status_code == 201

    # Now populated
    res_after = asyncio.run(
        client.get(
            f"/api/v1/documents/{doc.id}/shares",
            cookies={"docvault_session": alice_sess},
        )
    )
    assert res_after.status_code == 200
    shares = res_after.json()
    assert len(shares) == 1
    assert shares[0]["user_id"] == str(bob.id)
    assert shares[0]["username"] == "bob"
    assert "created_at" in shares[0]


def test_non_owner_cannot_list_document_shares(share_env) -> None:
    """Non-owner (even if a recipient of a share) receives 404 when listing shares."""
    client, session_factory, alice, bob, _, _, alice_sess, alice_csrf, bob_sess, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    # Bob tries to view shares before being shared -> 404
    res_before = asyncio.run(
        client.get(
            f"/api/v1/documents/{doc.id}/shares",
            cookies={"docvault_session": bob_sess},
        )
    )
    assert res_before.status_code == 404
    assert res_before.json()["detail"] == "Document not found"

    # Alice shares with Bob
    asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )

    # Bob tries to view shares after being shared -> still 404 (only owner can view shares)
    res_after = asyncio.run(
        client.get(
            f"/api/v1/documents/{doc.id}/shares",
            cookies={"docvault_session": bob_sess},
        )
    )
    assert res_after.status_code == 404


def test_owner_can_grant_share_successfully(share_env) -> None:
    """Document owner grants share; recipient sees document with access='shared'."""
    client, session_factory, alice, bob, _, _, alice_sess, alice_csrf, bob_sess, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice, "grant_test.pdf")

    # Bob has no documents initially
    res_bob_init = asyncio.run(
        client.get(
            "/api/v1/documents",
            cookies={"docvault_session": bob_sess},
        )
    )
    assert res_bob_init.status_code == 200
    assert len(res_bob_init.json()) == 0

    # Alice grants access to Bob
    res_grant = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res_grant.status_code == 201
    grant_data = res_grant.json()
    assert grant_data["user_id"] == str(bob.id)
    assert grant_data["username"] == "bob"

    # Bob now sees the document with access='shared'
    res_bob_after = asyncio.run(
        client.get(
            "/api/v1/documents",
            cookies={"docvault_session": bob_sess},
        )
    )
    assert res_bob_after.status_code == 200
    bob_docs = res_bob_after.json()
    assert len(bob_docs) == 1
    assert bob_docs[0]["id"] == str(doc.id)
    assert bob_docs[0]["access"] == "shared"
    assert bob_docs[0]["display_filename"] == "grant_test.pdf"


def test_grant_duplicate_share_rejected_with_conflict(share_env) -> None:
    """Granting duplicate share to the same user returns 409 Conflict."""
    client, session_factory, alice, bob, _, _, alice_sess, alice_csrf, _, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    # First grant succeeds
    res1 = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res1.status_code == 201

    # Second grant fails with 409
    res2 = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res2.status_code == 409
    assert res2.json()["detail"] == "Document is already shared with this user"


def test_grant_self_share_rejected_with_422(share_env) -> None:
    """Document owner attempting to share with themselves receives 422."""
    client, session_factory, alice, _, _, _, alice_sess, alice_csrf, _, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    res = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{alice.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res.status_code == 422
    assert res.json()["detail"] == "A document cannot be shared with its owner"


def test_grant_share_nonexistent_or_inactive_user_rejected_with_404(share_env) -> None:
    """Sharing with nonexistent user ID or inactive user returns 404."""
    client, session_factory, alice, _, _, inactive_user, alice_sess, alice_csrf, _, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    # Nonexistent user
    random_user_id = uuid4()
    res_random = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{random_user_id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res_random.status_code == 404
    assert res_random.json()["detail"] == "User not found"

    # Inactive user
    res_inactive = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{inactive_user.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res_inactive.status_code == 404
    assert res_inactive.json()["detail"] == "User not found"


def test_owner_can_revoke_share_successfully(share_env) -> None:
    """Document owner can revoke a share; recipient loses access; idempotent on second call."""
    client, session_factory, alice, bob, _, _, alice_sess, alice_csrf, bob_sess, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    # Grant share
    asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )

    # Verify Bob has access
    res_bob = asyncio.run(client.get("/api/v1/documents", cookies={"docvault_session": bob_sess}))
    assert len(res_bob.json()) == 1

    # Revoke share
    res_revoke = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res_revoke.status_code == 204

    # Bob no longer has access
    res_bob_after = asyncio.run(client.get("/api/v1/documents", cookies={"docvault_session": bob_sess}))
    assert len(res_bob_after.json()) == 0

    # Idempotent: revoking again also returns 204
    res_revoke_again = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )
    assert res_revoke_again.status_code == 204


def test_non_owner_cannot_grant_or_revoke_shares(share_env) -> None:
    """Non-owner (and shared recipient) cannot grant or revoke shares on the document."""
    client, session_factory, alice, bob, carol, _, alice_sess, alice_csrf, bob_sess, bob_csrf, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    # Bob tries to grant share to Carol without ownership -> 404
    res_bob_grant = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{carol.id}",
            cookies={"docvault_session": bob_sess},
            headers={"X-CSRF-Token": bob_csrf},
        )
    )
    assert res_bob_grant.status_code == 404

    # Bob tries to revoke share without ownership -> 404
    res_bob_del = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc.id}/shares/{carol.id}",
            cookies={"docvault_session": bob_sess},
            headers={"X-CSRF-Token": bob_csrf},
        )
    )
    assert res_bob_del.status_code == 404

    # Alice shares with Bob
    asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": alice_csrf},
        )
    )

    # Bob is now a recipient, but still cannot grant share to Carol -> 404
    res_recipient_grant = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{carol.id}",
            cookies={"docvault_session": bob_sess},
            headers={"X-CSRF-Token": bob_csrf},
        )
    )
    assert res_recipient_grant.status_code == 404

    # Recipient also cannot revoke other shares -> 404
    res_recipient_del = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc.id}/shares/{carol.id}",
            cookies={"docvault_session": bob_sess},
            headers={"X-CSRF-Token": bob_csrf},
        )
    )
    assert res_recipient_del.status_code == 404


def test_csrf_token_enforcement_on_share_mutations(share_env) -> None:
    """Mutating share requests (PUT and DELETE) strictly require a valid CSRF token."""
    client, session_factory, alice, bob, _, _, alice_sess, _, _, _, storage = share_env
    doc = _create_owned_document(session_factory, storage, alice)

    # 1. PUT without CSRF header -> 403 Forbidden
    res_put_no_csrf = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
        )
    )
    assert res_put_no_csrf.status_code == 403

    # 2. PUT with invalid CSRF header -> 403 Forbidden
    res_put_bad_csrf = asyncio.run(
        client.put(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": "invalid_csrf_token_value"},
        )
    )
    assert res_put_bad_csrf.status_code == 403

    # 3. DELETE without CSRF header -> 403 Forbidden
    res_del_no_csrf = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
        )
    )
    assert res_del_no_csrf.status_code == 403

    # 4. DELETE with invalid CSRF header -> 403 Forbidden
    res_del_bad_csrf = asyncio.run(
        client.delete(
            f"/api/v1/documents/{doc.id}/shares/{bob.id}",
            cookies={"docvault_session": alice_sess},
            headers={"X-CSRF-Token": "invalid_csrf_token_value"},
        )
    )
    assert res_del_bad_csrf.status_code == 403
