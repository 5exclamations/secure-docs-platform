import asyncio

from alembic import command
from alembic.config import Config
from sqlalchemy import text


async def test_migrations_roundtrip_and_match_models(owner_engine, services):
    """upgrade -> downgrade -> upgrade on a scratch database, then `alembic check` proves the ORM
    models and the migration history describe the same schema."""
    name = "migration_scratch"
    async with owner_engine.connect() as c:
        c = await c.execution_options(isolation_level="AUTOCOMMIT")
        await c.execute(text(f"DROP DATABASE IF EXISTS {name}"))
        await c.execute(text(f"CREATE DATABASE {name}"))
    url = services.owner_url.rsplit("/", 1)[0] + f"/{name}"
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "base")
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.check, cfg)
    async with owner_engine.connect() as c:
        c = await c.execution_options(isolation_level="AUTOCOMMIT")
        await c.execute(text(f"DROP DATABASE {name}"))
