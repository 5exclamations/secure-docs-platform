import os
import subprocess
import sys

from sqlalchemy import text
from sqlalchemy.engine import make_url


def _run(owner_url: str, password: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "MIGRATION_DATABASE_URL": owner_url, "APP_DB_PASSWORD": password}
    return subprocess.run(
        [sys.executable, "scripts/bootstrap_db_role.py"], env=env, capture_output=True, text=True, check=False
    )


def test_bootstrap_role_is_idempotent_and_handles_awkward_passwords(services):
    original = make_url(services.app_url).password  # the password the rest of the suite connects with
    assert original
    try:
        for _ in range(2):  # the second run takes the ALTER path
            out = _run(services.owner_url, "p'a\"ss;w0rd-with-quotes")
            assert out.returncode == 0, out.stderr
    finally:
        restored = _run(services.owner_url, original)  # never leave the shared role re-keyed
        assert restored.returncode == 0, restored.stderr


async def test_runtime_role_attributes(owner_engine):
    async with owner_engine.connect() as c:
        row = (
            await c.execute(
                text("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname='docs_app'")
            )
        ).one()
    assert tuple(row) == (False, False, False, False)
