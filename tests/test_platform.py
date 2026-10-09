import json
import uuid

import httpx
import jwt
import pytest
from app.clientip import client_ip
from app.config import Settings
from app.main import create_app
from app.observability import _redact
from app.security import PasswordPolicyError, validate_password
from app.uploads import sanitize_filename
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from tests.conftest import PASSWORD, next_ip

SECRET = "s" * 40


async def test_security_headers_and_request_id(client):
    r = await client.get("/health", headers={"X-Request-ID": "abc-12345678"})
    h = r.headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
    assert h["content-security-policy"].startswith("default-src 'none'")
    assert h["cache-control"] == "no-store" and h["referrer-policy"] == "no-referrer"
    assert h["x-request-id"] == "abc-12345678"
    bad = await client.get("/health", headers={"X-Request-ID": "x\ninjected"})
    assert bad.headers["x-request-id"] != "x\ninjected" and len(bad.headers["x-request-id"]) == 32


async def test_error_responses_also_carry_security_headers(client):
    r = await client.get("/api/v1/documents")
    assert r.status_code == 401 and r.headers["x-content-type-options"] == "nosniff"
    r404 = await client.get("/nope")
    assert r404.status_code == 404 and "content-security-policy" in r404.headers


async def test_cors_locked_to_configured_origins(make_settings):
    app = create_app(make_settings(cors_origins="https://app.example.com"))
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        ok = await c.options(
            "/api/v1/users/me",
            headers={"Origin": "https://app.example.com", "Access-Control-Request-Method": "GET"},
        )
        evil = await c.options(
            "/api/v1/users/me",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )
        assert ok.headers.get("access-control-allow-origin") == "https://app.example.com"
        assert "access-control-allow-origin" not in evil.headers
        await c.aclose()


async def test_no_cors_by_default(client):
    r = await client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


async def test_trusted_host_enforced_but_health_checks_exempt(make_settings):
    app = create_app(make_settings(allowed_hosts="api.example.com"))
    async with app.router.lifespan_context(app):
        good = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api.example.com")
        alb = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://10.20.11.5:8000")
        assert (await good.get("/health")).status_code == 200
        assert (await alb.get("/api/v1/users/me")).status_code == 400  # wrong Host header
        # the ALB health checker addresses targets by IP; it must not be refused
        assert (await alb.get("/health")).status_code == 200
        assert (await alb.get("/health/ready")).status_code == 200
        await good.aclose()
        await alb.aclose()


async def test_json_body_size_limit(client, new_org):
    await new_org()
    r = await client.post(
        "/api/v1/auth/login",
        content=b'{"email":"a@b.co","password":"' + b"x" * 2_000_000 + b'"}',
        headers={"Content-Type": "application/json", "X-Forwarded-For": next_ip()},
    )
    assert r.status_code == 413

    # a body that lies about / omits Content-Length is still cut off while streaming
    async def gen():
        for _ in range(40):
            yield b"x" * 65536

    r2 = await client.post(
        "/api/v1/auth/login",
        content=gen(),
        headers={"Content-Type": "application/json", "X-Forwarded-For": next_ip()},
    )
    assert r2.status_code == 413


async def test_unknown_fields_are_rejected(client, new_org):
    org = await new_org()
    r = await client.post(
        "/api/v1/users",
        headers=org.admin.h,
        json={
            "email": "x@example.com",
            "password": PASSWORD,
            "role": "viewer",
            "org_id": str(uuid.uuid4()),
        },
    )
    assert r.status_code == 422


async def test_error_bodies_do_not_leak_internals(client, new_org):
    org = await new_org()
    r = await client.get("/api/v1/documents/abc", headers=org.admin.h)
    assert "Traceback" not in r.text and "sqlalchemy" not in r.text.lower()


async def test_metrics_endpoint_counts_requests(app, client, new_org):
    org = await new_org()
    await client.get("/api/v1/users/me", headers=org.admin.h)
    text = (await client.get("/metrics")).text
    assert 'http_requests_total{method="GET",route="/api/v1/users/me",status="200"}' in text
    assert "http_request_duration_seconds_bucket" in text and "auth_events_total" in text
    assert "/api/v1/documents/" + uuid.uuid4().hex not in text  # route templates, not raw paths (bounded cardinality)


async def test_metrics_requires_token_when_configured(make_settings):
    app = create_app(make_settings(metrics_token="m" * 20))
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        assert (await c.get("/metrics")).status_code == 401
        assert (await c.get("/metrics", headers={"Authorization": "Bearer wrong"})).status_code == 401
        assert (await c.get("/metrics", headers={"Authorization": "Bearer " + "m" * 20})).status_code == 200
        await c.aclose()


async def test_readiness_reports_dependency_failure(app, client, monkeypatch):
    async def boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr(app.state.redis, "ping", boom)
    r = await client.get("/health/ready")
    assert (
        r.status_code == 503 and r.json()["detail"]["redis"] == "unavailable" and r.json()["detail"]["database"] == "ok"
    )
    assert "redis down" not in r.text


async def test_rate_limiter_fails_closed_when_redis_is_down(app, client, new_org, monkeypatch):
    org = await new_org()

    async def boom(*a, **k):
        raise ConnectionError("down")

    monkeypatch.setattr(app.state.limiter, "hit", boom)
    assert (await client.get("/api/v1/users/me", headers=org.admin.h)).status_code == 503


async def test_tracing_emits_spans_for_requests_and_queries(make_settings, tracing_processor, span_exporter):
    app = create_app(make_settings(), span_processor=tracing_processor)
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        await c.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": next_ip()},
            json={"email": "a@b.co", "password": "x"},
        )
        await c.get("/health")
        await c.aclose()
    names = [s.name for s in span_exporter.get_finished_spans()]
    assert any("POST /api/v1/auth/login" in n for n in names)
    assert any(n.startswith("SELECT") for n in names)  # SQLAlchemy instrumentation
    assert not any("/health" in n for n in names)  # health checks are excluded from tracing


def test_log_redaction():
    out = _redact(None, "info", {"event": "x", "password": "hunter2", "Authorization": "Bearer abc", "ok": 1})
    assert out["password"] == "[REDACTED]" and out["Authorization"] == "[REDACTED]" and out["ok"] == 1
    json.dumps(out)


def test_client_ip_resolution():
    class Req:
        def __init__(self, xff, peer="10.0.0.1"):
            self.headers = {"x-forwarded-for": xff} if xff else {}
            self.client = type("C", (), {"host": peer})()

    assert client_ip(Req("1.1.1.1"), 0) == "10.0.0.1"  # header ignored without trusted proxy
    assert client_ip(Req("6.6.6.6, 1.1.1.1"), 1) == "1.1.1.1"  # spoofed prefix ignored
    assert client_ip(Req("6.6.6.6, 1.1.1.1, 10.0.0.9"), 2) == "1.1.1.1"  # two proxies (CDN + ALB)
    assert client_ip(Req(None), 1) == "10.0.0.1"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\x\\evil.exe", "evil.exe"),
        ("", "file"),
        ("a\x00b.pdf", "a_b.pdf"),
        ("..", "file"),
        ("résumé final.pdf", "resume final.pdf"),
        ("a" * 400 + ".pdf", ("a" * 200)),
    ],
)
def test_filename_sanitization(raw, expected):
    assert sanitize_filename(raw) == expected


def test_password_policy():
    validate_password(PASSWORD, "someone@example.com")
    for pw, email in [("short", ""), ("alicealice1234", "alicealice@example.com"), ("a" * 12, "")]:
        with pytest.raises(PasswordPolicyError):
            validate_password(pw, email)


def test_production_config_is_validated():
    base = dict(
        _env_file=None,
        environment="production",
        jwt_secret=SECRET,
        allowed_hosts="api.example.com",
        enable_docs=False,
        metrics_token="m" * 20,
    )
    Settings(**base)
    for override in (
        {"jwt_secret": "short"},
        {"jwt_secret": "changeme"},
        {"cors_origins": "*"},
        {"allowed_hosts": "*"},
        {"enable_docs": True},
        {"metrics_token": None},
        {"jwt_secret": None},
    ):
        with pytest.raises(ValidationError):
            Settings(**{**base, **override})
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_algorithm="RS256")


async def test_docs_disabled_when_configured(make_settings):
    app = create_app(make_settings(enable_docs=False))
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        assert (await c.get("/docs")).status_code == 404 and (await c.get("/openapi.json")).status_code == 404
        await c.aclose()


async def test_rs256_tokens_jwks_and_alg_confusion(make_settings):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    pub = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    app = create_app(
        make_settings(jwt_algorithm="RS256", jwt_secret=None, jwt_private_key_pem=priv, jwt_public_key_pem=pub)
    )
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("203.0.113.5", 1)), base_url="http://t")
        slug = f"rs-{uuid.uuid4().hex[:8]}"
        email = f"{slug}@example.com"
        reg = await c.post(
            "/api/v1/auth/register",
            headers={"X-Forwarded-For": next_ip()},
            json={
                "organization_name": slug,
                "organization_slug": slug,
                "email": email,
                "password": PASSWORD,
            },
        )
        assert reg.status_code == 201
        tok = (
            await c.post(
                "/api/v1/auth/login",
                headers={"X-Forwarded-For": next_ip()},
                json={"email": email, "password": PASSWORD},
            )
        ).json()
        jwks = (await c.get("/.well-known/jwks.json")).json()
        assert jwks["keys"][0]["alg"] == "RS256" and "d" not in jwks["keys"][0]  # public part only
        header = jwt.get_unverified_header(tok["access_token"])
        assert header["alg"] == "RS256" and header["kid"] == jwks["keys"][0]["kid"]
        key_obj = jwt.PyJWK(jwks["keys"][0]).key
        claims = jwt.decode(tok["access_token"], key_obj, algorithms=["RS256"], audience="secure-docs-api")
        assert claims["org_id"] == reg.json()["org_id"]
        # classic algorithm-confusion attack: HS256 token "signed" with the public key
        import base64
        import hashlib
        import hmac
        import time

        def b64(b: bytes) -> bytes:
            return base64.urlsafe_b64encode(b).rstrip(b"=")

        head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = b64(json.dumps({**claims, "typ": "access", "exp": int(time.time()) + 600}).encode())
        sig = b64(hmac.new(pub.encode(), head + b"." + body, hashlib.sha256).digest())
        forged = (head + b"." + body + b"." + sig).decode()
        assert (await c.get("/api/v1/users/me", headers={"Authorization": f"Bearer {forged}"})).status_code == 401
        disc = (await c.get("/.well-known/openid-configuration")).json()
        assert (
            disc["jwks_uri"].endswith("/.well-known/jwks.json")
            and "RS256" in disc["id_token_signing_alg_values_supported"]
        )
        await c.aclose()


async def test_share_token_never_reaches_traces(make_settings, tracing_processor, span_exporter):
    app = create_app(make_settings(), span_processor=tracing_processor)
    token = "0" * 32 + ".VERY-SECRET-SHARE-TOKEN"
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        await c.post(f"/api/v1/shared/{token}/download", headers={"X-Forwarded-For": next_ip()})
        await c.aclose()
    spans = span_exporter.get_finished_spans()
    assert spans
    for span in spans:
        assert "VERY-SECRET" not in repr(dict(span.attributes or {})), span.name
        assert "VERY-SECRET" not in span.name


def test_scrub_url():
    from app.observability import scrub_url

    assert scrub_url("/api/v1/shared/abc.def/download") == "/api/v1/shared/{token}/download"
    assert scrub_url("http://h/api/v1/shared/abc.def/download?x=1") == "http://h/api/v1/shared/{token}/download?x=1"
    assert scrub_url("/api/v1/documents/1") == "/api/v1/documents/1"


async def test_api_refuses_to_start_with_a_role_that_bypasses_rls(make_settings, services):
    """Starting the API with the migration (owner) credentials would silently disable RLS."""
    app = create_app(make_settings(database_url=services.owner_url))
    with pytest.raises(RuntimeError, match="row level security"):
        async with app.router.lifespan_context(app):
            pass


async def test_traces_do_not_contain_credentials_or_bound_values(make_settings, tracing_processor, span_exporter):
    """SQL spans carry statement text with placeholders; emails and passwords must never appear."""
    app = create_app(make_settings(), span_processor=tracing_processor)
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        await c.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": next_ip()},
            json={"email": "trace.probe@example.com", "password": "Sup3r-Secret-Probe-Pw"},
        )
        await c.aclose()
    dump = repr([(s.name, dict(s.attributes or {})) for s in span_exporter.get_finished_spans()])
    assert "trace.probe" not in dump and "Sup3r-Secret" not in dump
