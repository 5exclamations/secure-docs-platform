"""Starts throwaway PostgreSQL, Redis and an S3 server (moto) for the test session when no external
services are configured. CI points TEST_* variables at service containers instead."""

from __future__ import annotations

import atexit
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_port(port: int, timeout: float = 30) -> None:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    raise TimeoutError(f"port {port} did not open")


@dataclass
class Services:
    owner_url: str
    app_url: str
    redis_url: str
    s3_endpoint: str
    s3_kind: str = "moto"
    s3_access_key: str = "x"
    s3_secret_key: str = "x"
    _procs: list[subprocess.Popen[bytes]] = field(default_factory=list)
    _tmp: Path | None = None
    _moto: object | None = None

    def stop(self) -> None:
        if self._moto is not None:
            self._moto.stop()  # type: ignore[attr-defined]
        for p in reversed(self._procs):
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)


def _start_s3(procs: list[subprocess.Popen[bytes]]) -> tuple[str, str, str, str, object | None]:
    """moto by default (fast, in-process). TEST_S3=minio runs a real MinIO server instead, which
    enforces presigned URL expiry and signatures (moto does not)."""
    if os.environ.get("TEST_S3") == "minio":
        binary = os.environ.get("MINIO_BIN") or shutil.which("minio")
        if not binary:
            raise RuntimeError("TEST_S3=minio but no minio binary (set MINIO_BIN)")
        data = Path(tempfile.mkdtemp(prefix="minio-data-"))
        atexit.register(shutil.rmtree, data, True)
        port = free_port()
        env = {**os.environ, "MINIO_ROOT_USER": "testminio", "MINIO_ROOT_PASSWORD": "testminio-secret-123"}
        procs.append(
            subprocess.Popen(
                [
                    binary,
                    "server",
                    str(data),
                    "--address",
                    f"127.0.0.1:{port}",
                    "--console-address",
                    f"127.0.0.1:{free_port()}",
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        _wait_port(port)
        return f"http://127.0.0.1:{port}", "minio", "testminio", "testminio-secret-123", None
    from moto.server import ThreadedMotoServer

    port = free_port()
    moto = ThreadedMotoServer(port=port, verbose=False)
    moto.start()
    return f"http://127.0.0.1:{port}", "moto", "x", "x", moto


def _pg_bin() -> Path | None:
    for cand in sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True):
        if (cand / "initdb").exists():
            return cand
    return None


def start_services() -> Services:
    procs: list[subprocess.Popen[bytes]] = []
    try:
        return _start(procs)
    except BaseException:
        for p in procs:
            p.terminate()
        raise


def _start(procs: list[subprocess.Popen[bytes]]) -> Services:
    if os.environ.get("TEST_DATABASE_OWNER_URL"):
        endpoint, kind, ak, sk, moto = _start_s3(procs)
        svc = Services(
            os.environ["TEST_DATABASE_OWNER_URL"],
            os.environ["TEST_DATABASE_APP_URL"],
            os.environ["TEST_REDIS_URL"],
            endpoint,
            kind,
            ak,
            sk,
        )
        svc._moto = moto
        svc._procs = procs
        return svc

    pg = _pg_bin()
    redis = shutil.which("redis-server")
    if pg is None or redis is None:
        raise RuntimeError("No TEST_* services configured and postgres/redis binaries not found")
    tmp = Path(tempfile.mkdtemp(prefix="docs-test-"))
    tmp.chmod(0o755)
    run_as: list[str] = ["runuser", "-u", "postgres", "--"] if os.geteuid() == 0 else []

    data = tmp / "pg"
    data.mkdir()
    if run_as:
        shutil.chown(data, "postgres", "postgres")
    pg_port = free_port()
    subprocess.run(
        [*run_as, str(pg / "initdb"), "-D", str(data), "-A", "trust", "-U", "postgres"],
        check=True,
        capture_output=True,
    )
    procs.append(
        subprocess.Popen(
            [
                *run_as,
                str(pg / "postgres"),
                "-D",
                str(data),
                "-p",
                str(pg_port),
                "-c",
                "listen_addresses=127.0.0.1",
                "-c",
                f"unix_socket_directories={data}",
                "-c",
                "fsync=off",
                "-c",
                "max_connections=200",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    )
    _wait_port(pg_port)
    time.sleep(1)
    psql = [
        *run_as,
        str(pg / "psql"),
        "-h",
        "127.0.0.1",
        "-p",
        str(pg_port),
        "-U",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
    ]
    subprocess.run([*psql, "-c", "CREATE DATABASE docs"], check=True, capture_output=True)
    subprocess.run(
        [*psql, "-c", "CREATE ROLE docs_app LOGIN PASSWORD 'docs_app' NOSUPERUSER NOBYPASSRLS"],
        check=True,
        capture_output=True,
    )

    redis_port = free_port()
    procs.append(
        subprocess.Popen(
            [
                redis,
                "--port",
                str(redis_port),
                "--save",
                "",
                "--appendonly",
                "no",
                "--bind",
                "127.0.0.1",
                "--dir",
                str(tmp),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    )
    _wait_port(redis_port)

    endpoint, kind, ak, sk, moto = _start_s3(procs)
    return Services(
        f"postgresql+asyncpg://postgres@127.0.0.1:{pg_port}/docs",
        f"postgresql+asyncpg://docs_app:docs_app@127.0.0.1:{pg_port}/docs",
        f"redis://127.0.0.1:{redis_port}/0",
        endpoint,
        kind,
        ak,
        sk,
        procs,
        tmp,
        moto,
    )
