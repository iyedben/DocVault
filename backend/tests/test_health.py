"""Tests for health route behavior without a live database or ASGI client."""

import pytest
from app.api.routes.health import health, ready, router
from fastapi import HTTPException
from sqlalchemy.exc import OperationalError


class SuccessfulSession:
    def execute(self, statement: object) -> None:
        assert str(statement) == "SELECT 1"


class UnavailableSession:
    def execute(self, _statement: object) -> None:
        raise OperationalError("SELECT 1", {}, RuntimeError("connection refused"))


def test_health_returns_http_200_without_database_dependency() -> None:
    route = next(route for route in router.routes if route.path == "/health")

    assert health() == {"status": "ok"}
    assert route.status_code == 200


def test_ready_returns_200_when_database_query_succeeds() -> None:
    route = next(route for route in router.routes if route.path == "/ready")
    response = ready(SuccessfulSession())  # type: ignore[arg-type]

    assert route.status_code == 200
    assert response == {"status": "ready"}


def test_ready_returns_503_when_database_query_fails() -> None:
    with pytest.raises(HTTPException) as error:
        ready(UnavailableSession())  # type: ignore[arg-type]

    assert error.value.status_code == 503
    assert error.value.detail == "Database unavailable"
    assert "connection refused" not in str(error.value.detail)
