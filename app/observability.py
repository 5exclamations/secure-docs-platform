"""Structured logging, Prometheus metrics and OpenTelemetry tracing."""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import CollectorRegistry, Counter, Histogram

from app.config import Settings

_SENSITIVE = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "secret",
    "cookie",
}


_SHARE_TOKEN = re.compile(r"(/shared/)[^/?#]+")


def scrub_url(value: str) -> str:
    """Share-link tokens are bearer secrets that live in the URL path: never record them."""
    return _SHARE_TOKEN.sub(r"\1{token}", value)


def _redact_span(span: Any, scope: dict[str, Any]) -> None:
    for key in ("http.target", "http.url", "url.path", "url.full", "http.route_raw"):
        value = span.attributes.get(key) if span.attributes else None
        if isinstance(value, str):
            span.set_attribute(key, scrub_url(value))


def _redact(_: Any, __: str, event: dict[str, Any]) -> dict[str, Any]:
    for key in list(event):
        if key.lower() in _SENSITIVE:
            event[key] = "[REDACTED]"
    return event


def _add_trace_ids(_: Any, __: str, event: dict[str, Any]) -> dict[str, Any]:
    ctx = trace.get_current_span().get_span_context()
    if ctx.is_valid:
        event["trace_id"] = format(ctx.trace_id, "032x")
        event["span_id"] = format(ctx.span_id, "016x")
    return event


def configure_logging(level: str = "INFO") -> None:
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_trace_ids,
        _redact,
        structlog.processors.format_exc_info,
    ]
    structlog.configure(
        processors=[*processors, structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    # Route stdlib loggers (uvicorn, sqlalchemy) through the same JSON formatter.
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").disabled = True  # replaced by our access log


class Metrics:
    """Per-app registry so tests can create many apps without duplicate-metric errors."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.http_requests = Counter(
            "http_requests_total",
            "HTTP requests",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.http_latency = Histogram(
            "http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route"],
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            registry=self.registry,
        )
        self.auth_events = Counter("auth_events_total", "Authentication events", ["event"], registry=self.registry)
        self.documents = Counter("document_events_total", "Document events", ["event"], registry=self.registry)
        self.rate_limited = Counter(
            "rate_limited_total", "Rejected by rate limiting", ["scope"], registry=self.registry
        )
        self.authz_denied = Counter("authz_denied_total", "Authorization denials", ["reason"], registry=self.registry)


def setup_tracing(
    app: FastAPI, settings: Settings, extra_processor: SpanProcessor | None = None
) -> TracerProvider | None:
    """Create a tracer provider and instrument the app. Disabled unless OTEL_ENABLED or a test
    processor is supplied. The provider is app-scoped (not the global one) to keep tests isolated."""
    if not (settings.otel_enabled or extra_processor):
        return None
    provider = TracerProvider(
        resource=Resource.create(
            {"service.name": settings.service_name, "deployment.environment": settings.environment}
        )
    )
    if settings.otel_enabled:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        endpoint = settings.otel_exporter_otlp_endpoint
        exporter = OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces") if endpoint else OTLPSpanExporter()
        provider.add_span_processor(BatchSpanProcessor(exporter))
    if extra_processor:
        provider.add_span_processor(extra_processor)
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(
        app, tracer_provider=provider, excluded_urls="health,metrics", server_request_hook=_redact_span
    )
    return provider
