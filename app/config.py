"""Application settings. Everything comes from environment variables; nothing is read from disk
except an optional local .env that is git-ignored. In AWS the values are injected from Secrets
Manager / SSM Parameter Store by the instance bootstrap (see infra/)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WEAK_SECRETS = {"changeme", "secret", "password", "change-me", "dev-secret", "test"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    environment: Literal["local", "test", "staging", "production"] = "local"
    service_name: str = "secure-docs-api"
    log_level: str = "INFO"
    enable_docs: bool = True

    # Data stores. The runtime role must NOT own the tables (row level security relies on it).
    database_url: str = "postgresql+asyncpg://docs_app:docs_app@localhost:5432/docs"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    redis_url: str = "redis://localhost:6379/0"

    # Tokens. HS256 by default, RS256 supported (publishes JWKS) for OIDC-style consumers.
    jwt_algorithm: Literal["HS256", "RS256"] = "HS256"
    jwt_secret: SecretStr | None = None
    jwt_private_key_pem: SecretStr | None = None
    jwt_public_key_pem: str | None = None
    jwt_key_id: str = "k1"
    jwt_issuer: str = "https://docs.example.internal"
    jwt_audience: str = "secure-docs-api"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 7 * 24 * 3600

    # Object storage
    s3_bucket: str = "secure-docs"
    s3_endpoint_url: str | None = None  # internal endpoint (MinIO in compose, None for AWS)
    s3_public_endpoint_url: str | None = None  # endpoint embedded in presigned URLs
    s3_region: str = "us-east-1"
    s3_access_key_id: str | None = None  # unset in AWS: instance role credentials are used
    s3_secret_access_key: SecretStr | None = None
    s3_force_path_style: bool = False
    s3_sse: Literal["", "AES256", "aws:kms"] = ""
    s3_kms_key_id: str | None = None
    presign_ttl_seconds: int = Field(default=60, ge=5, le=300)
    max_upload_bytes: int = 50 * 1024 * 1024
    max_json_body_bytes: int = 1024 * 1024

    # HTTP surface
    cors_origins: str = ""  # comma separated; empty = no cross-origin access
    allowed_hosts: str = "*"
    trusted_proxy_count: int = 0  # number of reverse proxies appending to X-Forwarded-For
    metrics_token: SecretStr | None = None

    # Rate limiting (fixed window, Redis backed)
    rate_limit_login_per_minute: int = 5
    rate_limit_user_per_minute: int = 100
    rate_limit_public_per_minute: int = 30
    login_lockout_threshold: int = 10
    login_lockout_seconds: int = 900

    # Telemetry
    otel_enabled: bool = False
    otel_exporter_otlp_endpoint: str | None = None

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_host_list(self) -> list[str]:
        return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]

    @property
    def is_production_like(self) -> bool:
        return self.environment in {"staging", "production"}

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.jwt_algorithm == "HS256":
            secret = self.jwt_secret.get_secret_value() if self.jwt_secret else ""
            if not secret:
                raise ValueError("JWT_SECRET is required when JWT_ALGORITHM=HS256")
            if self.is_production_like and (len(secret) < 32 or secret.lower() in _WEAK_SECRETS):
                raise ValueError("JWT_SECRET must be at least 32 random characters in staging/production")
        elif not (self.jwt_private_key_pem and self.jwt_public_key_pem):
            raise ValueError("RS256 requires JWT_PRIVATE_KEY_PEM and JWT_PUBLIC_KEY_PEM")
        if self.is_production_like:
            if "*" in self.cors_origin_list:
                raise ValueError("Wildcard CORS origin is not allowed in staging/production")
            if self.allowed_host_list == ["*"]:
                raise ValueError("ALLOWED_HOSTS must be set explicitly in staging/production")
            if self.enable_docs:
                raise ValueError("ENABLE_DOCS must be false in staging/production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
