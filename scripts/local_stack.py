"""Docker-free local stack: throwaway PostgreSQL + Redis + S3 (MinIO if MINIO_BIN is set, else moto)
plus the API on :8000. Handy where Docker is unavailable; `docker compose up` is the main path.

    TEST_S3=minio MINIO_BIN=/path/to/minio python scripts/local_stack.py
"""

import os
import signal
import subprocess
import sys
import time

import boto3
from alembic import command
from alembic.config import Config

sys.path.insert(0, ".")
from tests.infra import start_services

svc = start_services()
api = None
try:
    boto3.client(
        "s3",
        endpoint_url=svc.s3_endpoint,
        region_name="us-east-1",
        aws_access_key_id=svc.s3_access_key,
        aws_secret_access_key=svc.s3_secret_key,
    ).create_bucket(Bucket="secure-docs")
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", svc.owner_url)
    command.upgrade(cfg, "head")
    env = {
        **os.environ,
        "ENVIRONMENT": "local",
        "DATABASE_URL": svc.app_url,
        "REDIS_URL": svc.redis_url,
        "JWT_SECRET": os.urandom(32).hex(),
        "S3_BUCKET": "secure-docs",
        "S3_ENDPOINT_URL": svc.s3_endpoint,
        "S3_FORCE_PATH_STYLE": "true",
        "S3_ACCESS_KEY_ID": svc.s3_access_key,
        "S3_SECRET_ACCESS_KEY": svc.s3_secret_key,
    }
    api = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
            "--no-access-log",
            "--no-server-header",
        ],
        env=env,
    )
    print("API on http://127.0.0.1:8000  (Ctrl-C to stop)", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    while api.poll() is None:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    if api:
        api.terminate()
    svc.stop()
