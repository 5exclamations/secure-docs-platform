"""Pure ASGI middlewares (no BaseHTTPMiddleware, so contextvars and streaming behave)."""

from __future__ import annotations

import re
import time
import uuid

import structlog
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.observability import Metrics

log = structlog.get_logger("access")
_REQ_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
API_PREFIX = "/api/v1"
_UPLOAD_PATH = re.compile(r"^/api/v1/documents(/[0-9a-fA-F-]{36})?$")

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cache-control": "no-store",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# Swagger UI (dev only) needs its CDN assets; docs are disabled in staging/production.
DOCS_CSP = (
    "default-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        docs = scope["path"].startswith(("/docs", "/redoc"))

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for k, v in SECURITY_HEADERS.items():
                    headers.setdefault(k, v)
                headers.setdefault("content-security-policy", DOCS_CSP if docs else API_CSP)
                if self.hsts:
                    headers.setdefault("strict-transport-security", "max-age=63072000; includeSubDomains")
                if "server" in headers:
                    del headers["server"]
            await send(message)

        await self.app(scope, receive, wrapped)


class BodyTooLarge(Exception):
    pass


class RequestContextMiddleware:
    """Request id, body-size limit, access log and Prometheus metrics."""

    def __init__(self, app: ASGIApp, metrics: Metrics, max_upload: int, max_json: int) -> None:
        self.app = app
        self.metrics = metrics
        self.max_upload = max_upload
        self.max_json = max_json

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw = dict(scope["headers"])
        incoming = raw.get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _REQ_ID.match(incoming) else uuid.uuid4().hex
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        method = scope["method"]
        is_upload = method in {"POST", "PUT"} and bool(_UPLOAD_PATH.match(scope["path"]))
        limit = self.max_upload + 64 * 1024 if is_upload else self.max_json  # multipart overhead
        status = 500
        started = time.perf_counter()
        seen = 0
        response_started = False

        declared = raw.get(b"content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            await self._reject(scope, send, request_id)
            return

        rejected = False

        async def limited_receive() -> Message:
            nonlocal seen, rejected, status
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit and not rejected:
                    # Answer 413 ourselves: downstream frameworks would turn the abort into a 400.
                    rejected = True
                    status = 413
                    await self._reject(scope, send, request_id)
                    raise BodyTooLarge
            return message

        async def wrapped_send(message: Message) -> None:
            nonlocal status, response_started
            if rejected:
                return
            if message["type"] == "http.response.start":
                status = message["status"]
                response_started = True
                MutableHeaders(scope=message)["x-request-id"] = request_id
            await send(message)

        try:
            await self.app(scope, limited_receive, wrapped_send)
        except BodyTooLarge:
            pass  # 413 already sent by limited_receive
        except Exception:
            log.exception("unhandled_exception", method=method, path=scope["path"])
            raise
        finally:
            route = scope.get("route")
            template = getattr(route, "path", None)
            # FastAPI nests included routers, so the matched route path omits the include prefix.
            label = (
                (API_PREFIX if scope["path"].startswith(API_PREFIX + "/") else "") + template
                if template
                else "unmatched"
            )
            elapsed = time.perf_counter() - started
            self.metrics.http_requests.labels(method, label, str(status)).inc()
            self.metrics.http_latency.labels(method, label).observe(elapsed)
            if label not in {"/health", "/metrics"}:
                log.info(
                    "request",
                    method=method,
                    route=label,
                    status=status,
                    duration_ms=round(elapsed * 1000, 2),
                )

    async def _reject(self, scope: Scope, send: Send, request_id: str) -> None:
        body = b'{"detail":"Request body too large"}'
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"x-request-id", request_id.encode()),
            (b"connection", b"close"),
        ]
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": body})
