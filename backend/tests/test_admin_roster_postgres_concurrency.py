"""Opt-in PostgreSQL integration test for concurrent administrator removal.

Run through scripts/run_phase3_pg_concurrency_test.sh. The test connects only to
the disposable, loopback-published PostgreSQL instance started by that runner.
"""

from __future__ import annotations

import os
import re
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal

import pytest
from alembic import command
from alembic.config import Config
from app.models import Role, User
from app.services import users as user_service
from app.services.users import create_user
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

LOCK_ID = 7_421_991
DATABASE_PREFIX = "dv_p3_concurrency_"
LOCK_WAIT_TIMEOUT_SECONDS = 10
OPERATION_TIMEOUT_SECONDS = 45
_ROOT = Path(__file__).resolve().parents[2]


def _test_database_settings() -> tuple[str, int, str, str]:
    host = os.environ.get("PHASE3_TEST_PG_HOST", "")
    port_value = os.environ.get("PHASE3_TEST_PG_PORT", "")
    username = os.environ.get("PHASE3_TEST_PG_USER", "")
    password = os.environ.get("PHASE3_TEST_PG_PASSWORD", "")
    if host != "127.0.0.1" or not port_value.isdigit() or not username or not password:
        pytest.skip("Use the isolated PostgreSQL runner to provide loopback test settings")
    port = int(port_value)
    if not 1 <= port <= 65535:
        pytest.fail("Isolated PostgreSQL test port is invalid")
    if username != "phase3_test_admin":
        pytest.fail("Unexpected PostgreSQL user for isolated integration test")
    return host, port, username, password


def _new_engine(host: str, port: int, username: str, password: str, database: str) -> Engine:
    url = URL.create(
        "postgresql+psycopg",
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
    )
    return create_engine(
        url,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": 5,
            "options": "-c lock_timeout=30000 -c statement_timeout=40000",
        },
    )


def _apply_existing_migrations(engine: Engine) -> None:
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(_ROOT / "backend" / "migrations"))
    config.set_main_option("prepend_sys_path", str(_ROOT / "backend"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


@pytest.fixture
def isolated_postgres_engine() -> Engine:
    host, port, username, password = _test_database_settings()
    database_name = f"{DATABASE_PREFIX}{uuid.uuid4().hex}"
    if re.fullmatch(r"dv_p3_concurrency_[0-9a-f]{32}", database_name) is None:
        pytest.fail("Generated isolated database name failed its safety check")

    admin_engine = _new_engine(host, port, username, password, "postgres")
    database_created = False
    test_engine: Engine | None = None
    try:
        with admin_engine.connect() as connection:
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            identity = connection.execute(
                text("SELECT current_user, current_database()")
            ).one()
            if identity != ("phase3_test_admin", "postgres"):
                pytest.fail("Connection is not to the expected disposable PostgreSQL instance")
            isolation = connection.execute(text("SHOW transaction_isolation")).scalar_one()
            if isolation.lower() != "read committed":
                pytest.fail("Disposable PostgreSQL must use READ COMMITTED isolation")
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
            database_created = True

        test_engine = _new_engine(host, port, username, password, database_name)
        _apply_existing_migrations(test_engine)
        yield test_engine
    finally:
        if test_engine is not None:
            test_engine.dispose()
        try:
            if database_created:
                with admin_engine.connect() as connection:
                    connection = connection.execution_options(isolation_level="AUTOCOMMIT")
                    connection.execute(
                        text(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname = :database_name AND pid <> pg_backend_pid()"
                        ),
                        {"database_name": database_name},
                    )
                    connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{database_name}"')
        finally:
            admin_engine.dispose()


def test_concurrent_admin_removals_serialize_and_preserve_last_admin(
    isolated_postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = isolated_postgres_engine
    with engine.connect() as connection:
        assert connection.execute(text("SHOW transaction_isolation")).scalar_one().lower() == (
            "read committed"
        )
        assert connection.execute(text("SELECT current_database()")).scalar_one().startswith(
            DATABASE_PREFIX
        )

    with Session(engine, expire_on_commit=False) as setup_session:
        user_role = setup_session.scalar(select(Role).where(Role.name == "user"))
        admin_role = setup_session.scalar(select(Role).where(Role.name == "administrator"))
        assert user_role is not None
        assert admin_role is not None
        admin_a = create_user(
            setup_session,
            "concurrency_admin_a",
            f"{secrets.token_urlsafe(24)}Aa1!",
            role_name="administrator",
        )
        admin_b = create_user(
            setup_session,
            "concurrency_admin_b",
            f"{secrets.token_urlsafe(24)}Bb2!",
            role_name="administrator",
        )
        admin_a_id = admin_a.id
        admin_b_id = admin_b.id
        setup_session.commit()

    with engine.connect() as connection:
        assert connection.execute(
            text(
                "SELECT count(*) FROM users AS u JOIN roles AS r ON r.id = u.role_id "
                "WHERE u.is_active AND r.name = 'administrator'"
            )
        ).scalar_one() == 2

    holder_acquired = threading.Event()
    contender_attempting = threading.Event()
    release_holder = threading.Event()
    holder_pid: list[int] = []
    contender_pid: list[int] = []
    original_lock = user_service.lock_active_admin_roster

    def observed_lock(session: Session) -> None:
        operation = session.info["concurrent_operation"]
        if operation == "demote_a":
            original_lock(session)
            holder_pid.append(session.scalar(text("SELECT pg_backend_pid()")))
            holder_acquired.set()
            if not release_holder.wait(timeout=OPERATION_TIMEOUT_SECONDS):
                raise TimeoutError("Timed out while holding administrator roster lock")
        elif operation == "deactivate_b":
            if not holder_acquired.wait(timeout=LOCK_WAIT_TIMEOUT_SECONDS):
                raise TimeoutError("First operation did not acquire administrator roster lock")
            contender_pid.append(session.scalar(text("SELECT pg_backend_pid()")))
            contender_attempting.set()
            original_lock(session)
        else:
            original_lock(session)

    monkeypatch.setattr(user_service, "lock_active_admin_roster", observed_lock)

    def run_operation(operation: Literal["demote_a", "deactivate_b"]) -> str:
        with Session(
            engine, expire_on_commit=False, info={"concurrent_operation": operation}
        ) as session:
            try:
                user_id = admin_a_id if operation == "demote_a" else admin_b_id
                target = session.get(User, user_id)
                assert target is not None
                if operation == "demote_a":
                    user_service.change_user_role(session, target, "user")
                    return "committed"
                user_service.change_user_active_status(session, target, False)
                return "committed"
            except ValueError as exc:
                session.rollback()
                if str(exc) != "The final active administrator cannot be deactivated":
                    raise
                return "rejected"
            finally:
                if session.in_transaction():
                    session.rollback()

    def synchronized_operation(operation: Literal["demote_a", "deactivate_b"]) -> str:
        start.wait(timeout=5)
        return run_operation(operation)

    start = threading.Barrier(3)
    holder_future = None
    contender_future = None
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        holder_future = executor.submit(synchronized_operation, "demote_a")
        contender_future = executor.submit(synchronized_operation, "deactivate_b")
        start.wait(timeout=5)
        assert holder_acquired.wait(timeout=LOCK_WAIT_TIMEOUT_SECONDS)
        assert contender_attempting.wait(timeout=LOCK_WAIT_TIMEOUT_SECONDS)
        assert holder_pid and contender_pid

        deadline = time.monotonic() + LOCK_WAIT_TIMEOUT_SECONDS
        blocked_advisory_lock_seen = False
        while time.monotonic() < deadline:
            with engine.connect() as observer:
                blocked_advisory_lock_seen = bool(
                    observer.execute(
                        text(
                            "SELECT EXISTS ("
                            "SELECT 1 FROM pg_locks "
                            "WHERE locktype = 'advisory' "
                            "AND classid = 0::oid AND objid = CAST(:lock_id AS oid) "
                            "AND objsubid = 1 AND pid = :contender_pid AND NOT granted "
                            "AND EXISTS (SELECT 1 FROM pg_locks AS held "
                            "WHERE held.locktype = 'advisory' AND held.classid = 0::oid "
                            "AND held.objid = CAST(:lock_id AS oid) AND held.objsubid = 1 "
                            "AND held.pid = :holder_pid AND held.granted))"
                        ),
                        {
                            "lock_id": LOCK_ID,
                            "contender_pid": contender_pid[0],
                            "holder_pid": holder_pid[0],
                        },
                    ).scalar_one()
                )
            if blocked_advisory_lock_seen:
                break
            time.sleep(0.05)
        assert blocked_advisory_lock_seen, (
            "No waiting request for the shared advisory lock was observed"
        )
    finally:
        release_holder.set()
        executor.shutdown(wait=True, cancel_futures=True)
        worker_errors: list[BaseException] = []
        for future in (holder_future, contender_future):
            if future is not None:
                try:
                    future.result(timeout=OPERATION_TIMEOUT_SECONDS + 5)
                except BaseException as exc:  # noqa: BLE001 - surface worker failures on every path
                    worker_errors.append(exc)
        if worker_errors:
            raise RuntimeError("A PostgreSQL concurrency worker failed") from worker_errors[0]

    assert holder_future is not None
    assert contender_future is not None
    holder_result = holder_future.result(timeout=OPERATION_TIMEOUT_SECONDS + 5)
    contender_result = contender_future.result(timeout=OPERATION_TIMEOUT_SECONDS + 5)
    assert holder_result == "committed"
    assert contender_result == "rejected"

    with Session(engine) as verify_session:
        rows = verify_session.execute(
            text(
                "SELECT u.username, u.is_active, r.name AS role "
                "FROM users AS u JOIN roles AS r ON r.id = u.role_id "
                "ORDER BY u.username"
            )
        ).mappings().all()
        active_admin_count = verify_session.execute(
            text(
                "SELECT count(*) FROM users AS u JOIN roles AS r ON r.id = u.role_id "
                "WHERE u.is_active AND r.name = 'administrator'"
            )
        ).scalar_one()

    assert len(rows) == 2
    assert rows == [
        {"username": "concurrency_admin_a", "is_active": True, "role": "user"},
        {"username": "concurrency_admin_b", "is_active": True, "role": "administrator"},
    ]
    assert active_admin_count == 1
