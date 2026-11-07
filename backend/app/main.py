"""FastAPI application entry point."""

from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.routes.admin_users import router as admin_users_router
from app.api.routes.auth import router as auth_router
from app.api.routes.documents import router as documents_router
from app.api.routes.health import router as health_router
from app.api.routes.users import router as users_router
from app.middleware.document_limits import DocumentRequestLimitsMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware


def sanitized_validation_errors(
    errors: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return validation metadata without reflecting client-supplied values."""
    return [
        {
            "loc": error.get("loc", ()),
            "msg": error.get("msg", "Invalid request"),
            "type": error.get("type", "value_error"),
        }
        for error in errors
    ]


app = FastAPI(title="DocVault API")
app.add_middleware(DocumentRequestLimitsMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    _request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"detail": sanitized_validation_errors(exc.errors())},
    )


app.include_router(health_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(admin_users_router)
app.include_router(documents_router)
