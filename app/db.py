"""Async engine/session factory plus the tenant (row level security) binding.

Every request-scoped session carries ``session.info['org_id']``. On each transaction begin we run
``set_config('app.org_id', <uuid>, true)`` so PostgreSQL RLS policies see the tenant. The setting is
transaction-local, so a pooled connection can never leak one tenant's context into another request.
"""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, SessionTransaction

from app.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    return create_async_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@event.listens_for(Session, "after_begin")
def _apply_tenant(session: Session, _tx: SessionTransaction, connection: Connection) -> None:
    org_id = session.info.get("org_id")
    if org_id is not None:
        connection.execute(text("SELECT set_config('app.org_id', :org, true)"), {"org": str(org_id)})


async def set_tenant(session: AsyncSession, org_id: uuid.UUID) -> None:
    """Bind the session to a tenant for the current and all following transactions."""
    session.info["org_id"] = org_id
    await session.execute(text("SELECT set_config('app.org_id', :org, true)"), {"org": str(org_id)})


async def assert_unprivileged_db_role(engine: AsyncEngine, settings: Settings) -> None:
    """Row level security does not apply to superusers, BYPASSRLS roles or table owners. If the
    API were started with the migration (owner) credentials, tenant isolation would silently drop
    to the application layer only, so refuse to start (log loudly in local development)."""
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT r.rolsuper OR r.rolbypassrls AS bypass, "
                    "EXISTS (SELECT 1 FROM pg_tables t WHERE t.schemaname = 'public' "
                    "AND t.tablename = 'documents' AND t.tableowner = current_user) AS owner "
                    "FROM pg_roles r WHERE r.rolname = current_user"
                )
            )
        ).one()
    if row.bypass or row.owner:
        message = "database role can bypass row level security (superuser, BYPASSRLS or table owner)"
        if settings.environment != "local":
            raise RuntimeError(f"Refusing to start: {message}")
        structlog.get_logger().warning("rls_bypass_possible", detail=message)
