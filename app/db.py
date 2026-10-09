"""Async engine/session factory plus the tenant (row level security) binding.

Every request-scoped session carries ``session.info['org_id']``. On each transaction begin we run
``set_config('app.org_id', <uuid>, true)`` so PostgreSQL RLS policies see the tenant. The setting is
transaction-local, so a pooled connection can never leak one tenant's context into another request.
"""

from __future__ import annotations

import uuid

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
