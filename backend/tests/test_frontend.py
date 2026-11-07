"""Tests for FastAPI frontend integration, static file serving, and security headers."""

from __future__ import annotations

import asyncio
from collections.abc import Generator

import httpx
import pytest
from app.main import app


@pytest.fixture
def client() -> Generator[httpx.AsyncClient, None, None]:
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as c:
            yield c

    gen = run()
    val = asyncio.run(anext(gen))
    try:
        yield val
    finally:
        try:
            asyncio.run(anext(gen))
        except StopAsyncIteration:
            pass


def test_homepage_serves_valid_html_with_security_headers(client: httpx.AsyncClient) -> None:
    response = asyncio.run(client.get("/"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "no-cache" in response.headers.get("cache-control", "")

    # Security headers
    headers = response.headers
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "accelerometer=()" in headers["permissions-policy"]

    # CSP checks: strictly same-origin, no unsafe-inline or unsafe-eval
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "cdn.jsdelivr.net" not in csp

    # HTML content checks
    body = response.text
    assert "<!DOCTYPE html>" in body
    assert "<title>DocVault" in body
    assert 'id="main-navbar"' in body
    assert 'id="main-content"' in body
    assert 'id="notification-area"' in body
    assert '<link rel="stylesheet" href="/static/css/bootstrap.min.css">' in body
    assert '<link rel="stylesheet" href="/static/css/app.css">' in body
    assert '<script src="/static/vendor/bootstrap.bundle.min.js"></script>' in body
    assert '<script type="module" src="/static/js/app.js"></script>' in body

    # Verify no inline styles or scripts in the HTML document
    assert "<style" not in body
    assert 'style="' not in body


def test_static_css_serving(client: httpx.AsyncClient) -> None:
    # Bootstrap CSS
    bs_resp = asyncio.run(client.get("/static/css/bootstrap.min.css"))
    assert bs_resp.status_code == 200
    assert bs_resp.headers["content-type"].startswith("text/css")
    assert "Bootstrap" in bs_resp.text
    assert bs_resp.headers["x-frame-options"] == "DENY"
    assert bs_resp.headers["x-content-type-options"] == "nosniff"

    # Application CSS
    app_resp = asyncio.run(client.get("/static/css/app.css"))
    assert app_resp.status_code == 200
    assert app_resp.headers["content-type"].startswith("text/css")
    assert "--dv-navy" in app_resp.text


def test_static_js_serving(client: httpx.AsyncClient) -> None:
    # Bootstrap JS bundle
    bs_js_resp = asyncio.run(client.get("/static/vendor/bootstrap.bundle.min.js"))
    assert bs_js_resp.status_code == 200
    assert any(
        bs_js_resp.headers["content-type"].startswith(ct)
        for ct in ("text/javascript", "application/javascript")
    )
    assert "Bootstrap" in bs_js_resp.text

    # Application JS modules
    modules = [
        "/static/js/app.js",
        "/static/js/api.js",
        "/static/js/auth.js",
        "/static/js/auth-state.js",
        "/static/js/router.js",
        "/static/js/views/login.js",
        "/static/js/components/navbar.js",
        "/static/js/components/alerts.js",
        "/static/js/components/loading.js",
        "/static/js/utils/dom.js",
    ]
    for module_path in modules:
        resp = asyncio.run(client.get(module_path))
        assert resp.status_code == 200, f"Failed to load {module_path}"
        assert any(
            resp.headers["content-type"].startswith(ct)
            for ct in ("text/javascript", "application/javascript")
        )
        assert resp.headers["x-content-type-options"] == "nosniff"

    # Verify upload size limit constant in api.js aligns with backend 10 MiB limit
    api_js_resp = asyncio.run(client.get("/static/js/api.js"))
    assert "MAX_DOCUMENT_SIZE_BYTES = 10 * 1024 * 1024" in api_js_resp.text


def test_favicon_serving(client: httpx.AsyncClient) -> None:
    # Direct static path
    svg_resp = asyncio.run(client.get("/static/img/favicon.svg"))
    assert svg_resp.status_code == 200
    assert "image/svg+xml" in svg_resp.headers["content-type"]

    # Root /favicon.ico route
    ico_resp = asyncio.run(client.get("/favicon.ico"))
    assert ico_resp.status_code == 200
    assert "image/svg+xml" in ico_resp.headers["content-type"]


def test_static_nonexistent_returns_404(client: httpx.AsyncClient) -> None:
    response = asyncio.run(client.get("/static/css/nonexistent_file.css"))
    assert response.status_code == 404


def test_frontend_does_not_shadow_api_endpoints(client: httpx.AsyncClient) -> None:
    # Health endpoint
    health_resp = asyncio.run(client.get("/health"))
    assert health_resp.status_code == 200
    assert health_resp.json() == {"status": "ok"}

    # Auth API endpoint
    csrf_resp = asyncio.run(client.post("/api/v1/auth/csrf"))
    assert csrf_resp.status_code == 401
    assert csrf_resp.json()["detail"] == "Authentication required"
