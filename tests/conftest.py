from __future__ import annotations

import hashlib
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import boto3
import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config as AlembicConfig
from app.config import Settings
from app.main import create_app
from fastapi import FastAPI
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tests.infra import Services, start_services

BUCKET = "test-docs"
PASSWORD = "correct-horse-battery-9"


@pytest.fixture(scope="session")
def services() -> Any:
    try:
        svc: Services = start_services()
    except RuntimeError as exc:
        pytest.skip(str(exc))
    yield svc
    svc.stop()


@pytest.fixture(scope="session")
def migrated(services: Services) -> None:
    cfg = AlembicConfig("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", services.owner_url)
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
def make_settings(services: Services, migrated: None) -> Callable[..., Settings]:
    boto3.client(
        "s3",
        endpoint_url=services.s3_endpoint,
        region_name="us-east-1",
        aws_access_key_id=services.s3_access_key,
        aws_secret_access_key=services.s3_secret_key,
    ).create_bucket(Bucket=BUCKET)

    def factory(**overrides: Any) -> Settings:
        base: dict[str, Any] = dict(
            _env_file=None,
            environment="test",
            log_level="WARNING",
            database_url=services.app_url,
            redis_url=services.redis_url,
            jwt_secret="test-secret-test-secret-test-secret-0123",
            s3_bucket=BUCKET,
            s3_endpoint_url=services.s3_endpoint,
            s3_force_path_style=True,
            s3_access_key_id=services.s3_access_key,
            s3_secret_access_key=services.s3_secret_key,
            trusted_proxy_count=1,
            presign_ttl_seconds=60,
            rate_limit_login_per_minute=5,
            rate_limit_user_per_minute=100000,
            rate_limit_public_per_minute=30,
        )
        base.update(overrides)
        return Settings(**base)

    return factory


@pytest_asyncio.fixture(scope="session")
async def app(make_settings: Callable[..., Settings]) -> AsyncIterator[FastAPI]:
    application = create_app(make_settings())
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def _flush_redis(app: FastAPI) -> None:
    await app.state.redis.flushdb()


@pytest_asyncio.fixture
async def client(app: FastAPI, _flush_redis: None) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 4000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


_ip_counter = 0


def next_ip() -> str:
    global _ip_counter
    _ip_counter += 1
    return f"198.51.{(_ip_counter // 250) % 250}.{_ip_counter % 250 + 1}"


@dataclass
class Actor:
    id: str
    org_id: str
    email: str
    role: str
    token: str
    refresh: str

    @property
    def h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


async def login(client: httpx.AsyncClient, email: str, password: str = PASSWORD) -> httpx.Response:
    return await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers={"X-Forwarded-For": next_ip()},
    )


@dataclass
class Org:
    org_id: str
    admin: Actor
    client: httpx.AsyncClient

    async def add_user(self, role: str) -> Actor:
        email = f"{role}-{uuid.uuid4().hex[:8]}@example.com"
        r = await self.client.post(
            "/api/v1/users",
            headers=self.admin.h,
            json={"email": email, "password": PASSWORD, "role": role},
        )
        assert r.status_code == 201, r.text
        tok = (await login(self.client, email)).json()
        return Actor(r.json()["id"], self.org_id, email, role, tok["access_token"], tok["refresh_token"])


@pytest.fixture
def new_org(client: httpx.AsyncClient) -> Callable[[], Any]:
    async def make() -> Org:
        slug = f"org-{uuid.uuid4().hex[:10]}"
        email = f"admin-{uuid.uuid4().hex[:8]}@example.com"
        r = await client.post(
            "/api/v1/auth/register",
            headers={"X-Forwarded-For": next_ip()},
            json={
                "organization_name": slug,
                "organization_slug": slug,
                "email": email,
                "password": PASSWORD,
            },
        )
        assert r.status_code == 201, r.text
        user = r.json()
        tok = (await login(client, email)).json()
        admin = Actor(user["id"], user["org_id"], email, "admin", tok["access_token"], tok["refresh_token"])
        return Org(user["org_id"], admin, client)

    return make


PDF = b"%PDF-1.4\n%test document\n" + b"x" * 200


async def upload(
    client: httpx.AsyncClient,
    actor: Actor,
    content: bytes = PDF,
    *,
    title: str = "Report",
    content_type: str = "application/pdf",
    filename: str = "report.pdf",
    **form: str,
) -> httpx.Response:
    return await client.post(
        "/api/v1/documents",
        headers=actor.h,
        files={"file": (filename, content, content_type)},
        data={"title": title, **form},
    )


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def span_exporter() -> InMemorySpanExporter:
    return InMemorySpanExporter()


@pytest.fixture
def tracing_processor(span_exporter: InMemorySpanExporter) -> SimpleSpanProcessor:
    return SimpleSpanProcessor(span_exporter)


@pytest_asyncio.fixture(scope="session")
async def owner_engine(services: Services, migrated: None) -> AsyncIterator[Any]:
    """Superuser/owner connection used to simulate tampering or to inspect rows outside RLS."""
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(services.owner_url)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def app_engine(services: Services, migrated: None) -> AsyncIterator[Any]:
    """Connection as the *runtime* role, with no tenant bound, for raw RLS tests."""
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(services.app_url)
    yield engine
    await engine.dispose()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Tests that (transitively) use a live service fixture are integration tests."""
    live = {"services", "app", "client", "make_settings", "owner_engine", "app_engine", "migrated"}
    for item in items:
        if live & set(getattr(item, "fixturenames", ())):
            item.add_marker(pytest.mark.integration)
