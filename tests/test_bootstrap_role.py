import os
import subprocess
import sys

from sqlalchemy import text


def test_bootstrap_role_is_idempotent_and_unprivileged(services):
    env = {**os.environ, "MIGRATION_DATABASE_URL": services.owner_url, "APP_DB_PASSWORD": "p'a\"ss;w0rd-with-quotes"}
    for _ in range(2):  # second run takes the ALTER path
        out = subprocess.run(
            [sys.executable, "scripts/bootstrap_db_role.py"], env=env, capture_output=True, text=True, check=False
        )
        assert out.returncode == 0, out.stderr
    # restore the password the rest of the suite expects
    env["APP_DB_PASSWORD"] = "docs_app"
    assert subprocess.run([sys.executable, "scripts/bootstrap_db_role.py"], env=env, check=False).returncode == 0


async def test_runtime_role_attributes(owner_engine):
    async with owner_engine.connect() as c:
        row = (
            await c.execute(
                text("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname='docs_app'")
            )
        ).one()
    assert tuple(row) == (False, False, False, False)
