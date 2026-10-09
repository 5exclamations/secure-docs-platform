"""S3-compatible object store wrapper (MinIO locally, S3 in AWS). boto3 is synchronous, so calls
run in a worker thread."""

from __future__ import annotations

import asyncio
from typing import IO, Any

import boto3
from botocore.config import Config

from app.config import Settings


class ObjectStore:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        cfg = Config(
            signature_version="s3v4",
            s3={"addressing_style": "path" if settings.s3_force_path_style else "auto"},
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=3,
            read_timeout=30,
        )
        creds: dict[str, Any] = {}
        if settings.s3_access_key_id and settings.s3_secret_access_key:
            creds = {
                "aws_access_key_id": settings.s3_access_key_id,
                "aws_secret_access_key": settings.s3_secret_access_key.get_secret_value(),
            }
        self._client = boto3.client(
            "s3",
            region_name=settings.s3_region,
            endpoint_url=settings.s3_endpoint_url,
            config=cfg,
            **creds,
        )
        # Presigned URLs must carry the host the *browser* can reach (e.g. localhost:9000 for MinIO
        # while the API talks to minio:9000). Signing is offline, no network call is made.
        self._signer = boto3.client(
            "s3",
            region_name=settings.s3_region,
            endpoint_url=settings.s3_public_endpoint_url or settings.s3_endpoint_url,
            config=cfg,
            **creds,
        )

    @property
    def bucket(self) -> str:
        return self._s.s3_bucket

    def _put_sync(self, key: str, fileobj: IO[bytes], content_type: str, sha256_hex: str) -> None:
        extra: dict[str, Any] = {"ContentType": content_type, "Metadata": {"sha256": sha256_hex}}
        if self._s.s3_sse:
            extra["ServerSideEncryption"] = self._s.s3_sse
            if self._s.s3_sse == "aws:kms" and self._s.s3_kms_key_id:
                extra["SSEKMSKeyId"] = self._s.s3_kms_key_id
        fileobj.seek(0)
        self._client.upload_fileobj(fileobj, self.bucket, key, ExtraArgs=extra)

    async def put(self, key: str, fileobj: IO[bytes], content_type: str, sha256_hex: str) -> None:
        await asyncio.to_thread(self._put_sync, key, fileobj, content_type, sha256_hex)

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._client.delete_object, Bucket=self.bucket, Key=key)

    def presign_get(self, key: str, filename: str, content_type: str, ttl: int) -> str:
        safe = filename.replace('"', "").replace("\\", "")
        return str(
            self._signer.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.bucket,
                    "Key": key,
                    "ResponseContentDisposition": f'attachment; filename="{safe}"',
                    "ResponseContentType": content_type,
                },
                ExpiresIn=ttl,
            )
        )

    async def ping(self) -> None:
        await asyncio.to_thread(self._client.head_bucket, Bucket=self.bucket)
