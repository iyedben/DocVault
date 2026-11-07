"""FastAPI application entry point."""

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

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


def _resolve_frontend_dir() -> Path:
    env_dir = os.getenv("FRONTEND_DIR")
    if env_dir:
        candidate = Path(env_dir)
        if candidate.is_dir():
            return candidate
    repo_root = Path(__file__).resolve().parents[2] / "frontend"
    if repo_root.is_dir():
        return repo_root
    container_root = Path(__file__).resolve().parents[1] / "frontend"
    if container_root.is_dir():
        return container_root
    cwd_dir = Path.cwd() / "frontend"
    if cwd_dir.is_dir():
        return cwd_dir
    return repo_root


FRONTEND_DIR = _resolve_frontend_dir()
STATIC_DIR = FRONTEND_DIR / "static"
INDEX_HTML = FRONTEND_DIR / "index.html"
FAVICON_FILE = STATIC_DIR / "img" / "favicon.svg"

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def serve_index() -> Response:
    if not INDEX_HTML.is_file():
        return JSONResponse(
            status_code=404,
            content={"detail": "Frontend index.html not found"},
        )
    return FileResponse(
        str(INDEX_HTML),
        media_type="text/html",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/favicon.ico", include_in_schema=False)
def serve_favicon() -> Response:
    if FAVICON_FILE.is_file():
        return FileResponse(str(FAVICON_FILE), media_type="image/svg+xml")
    return Response(status_code=204)
