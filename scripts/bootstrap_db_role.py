"""Creates (or re-keys) the least-privilege runtime role `docs_app`.

Run once per environment, as the database owner, before `alembic upgrade head`:
    MIGRATION_DATABASE_URL=... APP_DB_PASSWORD=... python scripts/bootstrap_db_role.py

The role is NOSUPERUSER / NOBYPASSRLS and never owns tables, so row level security always applies
to the API. Idempotent: safe to run on every deploy.
"""

import asyncio
import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

ROLE = "docs_app"


async def main() -> None:
    url = os.environ["MIGRATION_DATABASE_URL"]
    password = os.environ["APP_DB_PASSWORD"]
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        exists = (await conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": ROLE})).first()
        verb = "ALTER" if exists else "CREATE"
        # DDL cannot take bind parameters; quote the password as a literal via the server.
        literal = (await conn.execute(text("SELECT quote_literal(:p)"), {"p": password})).scalar_one()
        await conn.execute(
            text(f"{verb} ROLE {ROLE} LOGIN PASSWORD {literal} NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS")
        )
        dbname = (await conn.execute(text("SELECT current_database()"))).scalar_one()
        await conn.execute(text(f'GRANT CONNECT ON DATABASE "{dbname}" TO {ROLE}'))
    await engine.dispose()
    print(f"role {ROLE} ready")


if __name__ == "__main__":
    asyncio.run(main())
