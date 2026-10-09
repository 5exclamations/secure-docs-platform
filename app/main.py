from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry.sdk.trace import SpanProcessor
from redis.asyncio import Redis
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import Settings, get_settings
from app.db import create_engine, create_session_factory
from app.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.observability import Metrics, configure_logging, setup_tracing
from app.redis_stores import RateLimiter, TokenStore
from app.routers import audit, auth, documents, health, shared, users
from app.security import TokenService
from app.storage import ObjectStore

DESCRIPTION = """
Multi-tenant document management API.

* Every organization is a hard tenant boundary (application checks, composite foreign keys and
  PostgreSQL row level security).
* Authenticate with `POST /api/v1/auth/login`, then send `Authorization: Bearer <access_token>`.
* Downloads are short-lived pre-signed object-storage URLs; the API never proxies file bytes.
"""


def create_app(settings: Settings | None = None, span_processor: SpanProcessor | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    metrics = Metrics()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine(settings)
        redis: Redis = Redis.from_url(settings.redis_url, decode_responses=True)
        app.state.engine = engine
        app.state.session_factory = create_session_factory(engine)
        app.state.redis = redis
        app.state.token_store = TokenStore(redis, settings.refresh_token_ttl_seconds)
        app.state.limiter = RateLimiter(redis)
        app.state.store = ObjectStore(settings)
        if app.state.tracer_provider is not None:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

            SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine, tracer_provider=app.state.tracer_provider)
        structlog.get_logger().info("startup", environment=settings.environment)
        try:
            yield
        finally:
            await redis.aclose()
            await engine.dispose()

    docs = "/docs" if settings.enable_docs else None
    app = FastAPI(
        title="Secure Document Platform",
        version="1.0.0",
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url=docs,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.settings = settings
    app.state.metrics = metrics
    app.state.tokens = TokenService(settings)

    # Order matters: the last added is the outermost. Request context wraps everything so even
    # rejected hosts/CORS preflights get a request id, metrics and security headers.
    if settings.allowed_host_list != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
            expose_headers=["X-Request-ID", "Retry-After"],
            allow_credentials=False,
            max_age=600,
        )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production_like)
    app.add_middleware(
        RequestContextMiddleware,
        metrics=metrics,
        max_upload=settings.max_upload_bytes,
        max_json=settings.max_json_body_bytes,
    )

    app.include_router(health.router)
    for r in (auth.router, users.router, documents.router, shared.router, audit.router):
        app.include_router(r, prefix="/api/v1")

    app.state.tracer_provider = setup_tracing(app, settings, span_processor)
    return app
