"""Alembic environment. Migrations run as the schema OWNER (MIGRATION_DATABASE_URL); the API runs
as a different, non-owner role so that row level security applies to it."""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from app.models import Base
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata


def _url() -> str:
    url = (
        config.get_main_option("sqlalchemy.url")
        or os.environ.get("MIGRATION_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
    )
    if not url:
        raise RuntimeError("Set MIGRATION_DATABASE_URL")
    return url


# Alembic cannot compare functional (expression) GIN indexes reliably and reports a permanent
# false diff for this one; it is created explicitly in the migration and covered by search tests.
_UNCOMPARABLE = {"ix_documents_search"}


def _include_object(obj: object, name: str | None, type_: str, reflected: bool, compare_to: object) -> bool:
    return not (type_ == "index" and name in _UNCOMPARABLE)


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _online() -> None:
    engine = create_async_engine(_url(), poolclass=pool.NullPool)
    async with engine.connect() as conn:
        await conn.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_online())
