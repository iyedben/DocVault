"""Application-wide security headers middleware."""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import AuthSettings

DOCS_PATHS = {"/docs", "/redoc", "/openapi.json"}
API_V1_PREFIX = "/api/v1"

CSP_APP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

CSP_DOCS = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

PERMISSIONS_POLICY = (
    "accelerometer=(), "
    "camera=(), "
    "geolocation=(), "
    "gyroscope=(), "
    "magnetometer=(), "
    "microphone=(), "
    "payment=(), "
    "usb=()"
)


class SecurityHeadersMiddleware:
    """Enforce central HTTP security and caching headers across all endpoints."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        is_docs = path in DOCS_PATHS or path.startswith(("/docs/", "/redoc/"))
        is_api_v1 = path == API_V1_PREFIX or path.startswith(API_V1_PREFIX + "/")

        csp_value = CSP_DOCS if is_docs else CSP_APP

        settings = AuthSettings.from_environment()
        include_hsts = settings.cookie_secure

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                managed_lower = {
                    b"x-frame-options",
                    b"x-content-type-options",
                    b"referrer-policy",
                    b"permissions-policy",
                    b"content-security-policy",
                    b"strict-transport-security",
                }
                if is_api_v1:
                    managed_lower.add(b"cache-control")

                existing_headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in managed_lower
                ]

                existing_headers.extend(
                    [
                        (b"x-frame-options", b"DENY"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", PERMISSIONS_POLICY.encode("ascii")),
                        (b"content-security-policy", csp_value.encode("ascii")),
                    ]
                )

                if is_api_v1:
                    existing_headers.append((b"cache-control", b"private, no-store"))

                if include_hsts:
                    existing_headers.append(
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                    )

                message = {**message, "headers": existing_headers}
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
