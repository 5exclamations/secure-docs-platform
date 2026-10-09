"""Renders the EC2 boot script with Terraform's templatefile(), runs it against stubbed `aws`,
`docker`, `dnf` and `systemctl` commands inside a temporary root, and then loads the environment
file it generated into the application's own production settings validation.

It proves the script is syntactically valid, takes the expected steps in order for both the
ElastiCache and the local-Redis branch, never embeds secrets in the script text, URL-encodes an
awkward RDS password, and produces a configuration the application accepts in production mode.
It does NOT prove anything about real AWS behavior (IAM, IMDS, ECR, Docker on Amazon Linux).

    python infra/tests/verify_user_data.py        # needs terraform on PATH and the app requirements
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app.config import Settings

TEMPLATE = ROOT / "infra/modules/compute/user_data.sh.tftpl"
RDS_PASSWORD = "Ab/c+d=e:f@g#h?i%j&k!l"  # characters that break naive URL building
APP_SECRET = {
    "jwt_secret": "j" * 64,
    "app_db_password": "AppDbPass1234567890abcdefghijklmnopqrstuv",
    "metrics_token": "MetricsToken1234567890abcdefghijklmnop",
}
REDIS_TOKEN = "RedisAuthToken1234567890abcdefghijklmnopqrstuv"

TF = """
variable "with_redis" { type = bool }
output "script" {
  value = templatefile("__TEMPLATE__", {
    region = "us-east-1", account_id = "111111111111",
    image_uri = "111111111111.dkr.ecr.us-east-1.amazonaws.com/secure-docs-dev-api:abc123",
    app_secret_arn = "arn:app-secret", db_secret_arn = "arn:db-secret", db_host = "db.example.internal",
    redis_endpoint = var.with_redis ? "redis.example.internal" : "",
    redis_secret_arn = var.with_redis ? "arn:redis-secret" : "",
    bucket = "secure-docs-111111111111-docs", kms_key_arn = "arn:aws:kms:us-east-1:111111111111:key/abc",
    log_group = "/secure-docs-dev/api", cors_origins = "", allowed_hosts = "docs.example.com",
    jwt_issuer = "https://docs.example.com",
  })
}
""".replace("__TEMPLATE__", str(TEMPLATE))


def sh(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kw)  # type: ignore[call-overload]


def render(tmp: Path, with_redis: bool) -> str:
    work = tmp / f"tf-{with_redis}"
    work.mkdir()
    (work / "main.tf").write_text(TF)
    assert sh(["terraform", "init", "-input=false"], cwd=work).returncode == 0
    res = sh(
        ["terraform", "apply", "-auto-approve", "-input=false", f"-var=with_redis={str(with_redis).lower()}"], cwd=work
    )
    assert res.returncode == 0, res.stderr
    return sh(["terraform", "output", "-raw", "script"], cwd=work).stdout


def make_stubs(tmp: Path) -> Path:
    stubs = tmp / "bin"
    stubs.mkdir()
    log = tmp / "calls.log"
    secrets = {
        "arn:app-secret": json.dumps(APP_SECRET),
        "arn:db-secret": json.dumps({"username": "docs_owner", "password": RDS_PASSWORD}),
        "arn:redis-secret": REDIS_TOKEN,
    }
    (stubs / "aws").write_text(
        "#!/usr/bin/env python3\nimport sys, json\n"
        f"open({str(log)!r}, 'a').write('aws ' + ' '.join(sys.argv[1:]) + '\\n')\n"
        f"S = {secrets!r}\n"
        "a = sys.argv[1:]\n"
        "if 'get-secret-value' in a: print(S[a[a.index('--secret-id') + 1]])\n"
        "elif 'get-login-password' in a: print('ecr-token')\n"
    )
    (stubs / "docker").write_text(
        f'#!/bin/bash\necho "docker $*" >> {log}\ncase "$1" in login) cat > /dev/null;; esac\n'
    )
    for name in ("dnf", "systemctl"):
        (stubs / name).write_text(f'#!/bin/bash\necho "{name} $*" >> {log}\n')
    for f in stubs.iterdir():
        f.chmod(0o755)
    return stubs


def load_env(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)


def check(cond: bool, msg: str) -> None:
    print(f"  [{'ok  ' if cond else 'FAIL'}] {msg}")
    if not cond:
        raise SystemExit(1)


def main() -> int:
    if not shutil.which("terraform"):
        print("terraform not on PATH")
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="userdata-"))
    try:
        stubs = make_stubs(tmp)
        for with_redis in (True, False):
            print(f"== boot script, ElastiCache={'yes' if with_redis else 'no (local redis container)'}")
            script = render(tmp, with_redis)
            leaked = [x for x in (RDS_PASSWORD, *APP_SECRET.values(), REDIS_TOKEN) if x in script]
            check(not leaked, "no secret value is embedded in the user-data text")
            root = tmp / f"root-{with_redis}"
            for rel in ("etc/secure-docs", "etc/systemd/system", "var/log"):
                (root / rel).mkdir(parents=True)
            sandboxed = (
                script.replace("/etc/secure-docs", f"{root}/etc/secure-docs")
                .replace("/etc/systemd/system", f"{root}/etc/systemd/system")
                .replace("/var/log/user-data.log", f"{root}/var/log/user-data.log")
            )
            (tmp / "calls.log").write_text("")
            res = sh(["bash", "-c", sandboxed], env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"})
            check(res.returncode == 0, f"script completes (exit {res.returncode}) {res.stderr[-200:]}")
            calls = (tmp / "calls.log").read_text().splitlines()
            order = [
                "docker login",
                "docker pull",
                "docker network create",
                "docker run --rm --env-file",
                "docker run --rm --env-file",
            ]
            idx = [next(i for i, c in enumerate(calls) if c.startswith(o)) for o in order[:3]]
            check(idx == sorted(idx), "login, pull and network creation happen in order")
            runs = [c for c in calls if c.startswith("docker run --rm")]
            check(
                "bootstrap_db_role.py" in runs[0] and "alembic upgrade head" in runs[1],
                "DB role bootstrap runs before the migration",
            )
            check(
                any(c.startswith("systemctl enable --now secure-docs") for c in calls), "service is enabled and started"
            )
            check(
                with_redis != any("redis-server" in c for c in calls), "local redis container only without ElastiCache"
            )

            env = load_env(root / "etc/secure-docs/api.env")
            settings = Settings(_env_file=None, **{k.lower(): v for k, v in env.items()})  # type: ignore[arg-type]
            check(
                settings.environment == "production" and not settings.enable_docs,
                "env file passes production validation",
            )
            check(
                settings.s3_sse == "aws:kms" and settings.trusted_proxy_count == 1,
                "KMS encryption and ALB proxy count are set",
            )
            check(make_url(settings.database_url).username == "docs_app", "the API connects as the unprivileged role")
            check(
                settings.redis_url.startswith("rediss://" if with_redis else "redis://"),
                "redis URL scheme matches the topology",
            )
            migrate = load_env(root / "etc/secure-docs/migrate.env")
            check(
                make_url(migrate["MIGRATION_DATABASE_URL"]).password == RDS_PASSWORD,
                "awkward RDS password survives URL encoding",
            )
            check(make_url(migrate["MIGRATION_DATABASE_URL"]).username == "docs_owner", "migrations use the owner role")
            mode = (root / "etc/secure-docs/api.env").stat().st_mode & 0o777
            check(mode == 0o600, f"env file is 0600 (got {oct(mode)})")
            unit = (root / "etc/systemd/system/secure-docs.service").read_text()
            check(
                all(
                    f in unit
                    for f in (
                        "--read-only",
                        "--cap-drop ALL",
                        "no-new-privileges",
                        "--log-driver awslogs",
                        "Restart=always",
                    )
                ),
                "systemd unit starts a hardened container with CloudWatch logging",
            )
        print("\nUSER-DATA CHECKS PASSED")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
