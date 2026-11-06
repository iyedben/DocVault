"""Bound document request bodies before Starlette multipart parsing."""

from __future__ import annotations

import threading
from collections.abc import Awaitable, Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import DocumentSettings

DOCUMENTS_PATH = "/api/v1/documents"


class RequestBodyTooLarge(Exception):
    """Raised before a request body over the configured boundary is forwarded."""


class DocumentRequestLimitsMiddleware:
    """Add private cache headers and cap/admit document uploads before parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._upload_gate = threading.Lock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        is_document_request = path == DOCUMENTS_PATH or path.startswith(
            DOCUMENTS_PATH + "/"
        )
        if not is_document_request:
            await self.app(scope, receive, send)
            return

        async def send_with_private_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower()
                    not in {b"cache-control", b"x-content-type-options"}
                ]
                response_headers.extend(
                    [
                        (b"cache-control", b"private, no-store"),
                        (b"x-content-type-options", b"nosniff"),
                    ]
                )
                message = {**message, "headers": response_headers}
            await send(message)

        is_upload = scope.get("method") == "POST" and path == DOCUMENTS_PATH
        if not is_upload:
            await self.app(scope, receive, send_with_private_headers)
            return

        if not self._upload_gate.acquire(blocking=False):
            await self._send_json(
                send_with_private_headers,
                429,
                b'{"detail":"An upload is already in progress"}',
                [(b"retry-after", b"1")],
            )
            return

        try:
            settings = DocumentSettings.from_environment()
            content_length = self._content_length(scope)
            if content_length is not None and content_length > settings.max_request_body_size_bytes:
                await self._send_json(
                    send_with_private_headers,
                    413,
                    b'{"detail":"Request body exceeds the maximum permitted size"}',
                )
                return

            state = scope.setdefault("state", {})
            received_bytes = 0

            async def limited_receive() -> Message:
                nonlocal received_bytes
                message = await receive()
                if message["type"] == "http.request":
                    received_bytes += len(message.get("body", b""))
                    state["document_request_bytes"] = received_bytes
                    if received_bytes > settings.max_request_body_size_bytes:
                        raise RequestBodyTooLarge
                return message

            response_started = False

            async def track_response(message: Message) -> None:
                nonlocal response_started
                if message["type"] == "http.response.start":
                    response_started = True
                await send_with_private_headers(message)

            try:
                await self.app(scope, limited_receive, track_response)
            except RequestBodyTooLarge:
                if not response_started:
                    await self._send_json(
                        send_with_private_headers,
                        413,
                        b'{"detail":"Request body exceeds the maximum permitted size"}',
                    )
        finally:
            self._upload_gate.release()

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        values = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"content-length"
        ]
        if not values:
            return None
        if len(values) != 1 or not values[0].isdigit():
            return None
        try:
            return int(values[0])
        except ValueError:
            return None

    @staticmethod
    async def _send_json(
        send: Callable[[Message], Awaitable[None]],
        status_code: int,
        body: bytes,
        extra_headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": body})
