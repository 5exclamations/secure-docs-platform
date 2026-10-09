from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
Tag = Annotated[str, StringConstraints(min_length=1, max_length=50, pattern=r"^[\w .:+-]+$")]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_name: str = Field(min_length=2, max_length=200)
    organization_slug: Slug
    email: EmailStr
    password: str = Field(max_length=128)
    full_name: str = Field(default="", max_length=200)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(max_length=128)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: str = Field(max_length=2048)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class OrgOut(ORM):
    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class UserOut(ORM):
    id: uuid.UUID
    org_id: uuid.UUID
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(max_length=128)
    full_name: str = Field(default="", max_length=200)
    role: Literal["admin", "editor", "viewer"] = "viewer"


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["admin", "editor", "viewer"] | None = None
    is_active: bool | None = None


class DocumentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    tags: list[Tag] | None = Field(default=None, max_length=20)


def parse_tags(raw: str | None) -> list[str]:
    """Tags arrive as a comma separated multipart field."""
    if not raw:
        return []
    tags = [t.strip() for t in raw.split(",") if t.strip()]
    if len(tags) > 20 or any(len(t) > 50 or not re.fullmatch(r"[\w .:+-]+", t) for t in tags):
        raise ValueError("Invalid tags")
    return list(dict.fromkeys(tags))


class VersionOut(ORM):
    version: int
    original_filename: str
    content_type: str
    size_bytes: int
    checksum_sha256: str
    uploaded_by: uuid.UUID
    created_at: datetime


class DocumentOut(ORM):
    id: uuid.UUID
    org_id: uuid.UUID
    owner_id: uuid.UUID
    title: str
    description: str | None
    tags: list[str]
    current_version: int
    created_at: datetime
    updated_at: datetime


class DocumentDetail(DocumentOut):
    latest: VersionOut | None = None
    my_access: list[str] = []


class DocumentPage(BaseModel):
    items: list[DocumentOut]
    total: int
    limit: int
    offset: int


class DownloadOut(BaseModel):
    url: str
    expires_at: datetime
    filename: str
    sha256: str
    version: int


class PermissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: uuid.UUID
    level: Literal["read", "write"]
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def _tz_aware(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return v


class PermissionOut(ORM):
    id: uuid.UUID
    document_id: uuid.UUID
    user_id: uuid.UUID
    level: str
    expires_at: datetime | None
    granted_by: uuid.UUID
    created_at: datetime


class ShareLinkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expires_in_seconds: int = Field(ge=60, le=30 * 24 * 3600, default=3600)
    max_downloads: int | None = Field(default=None, ge=1, le=10_000)


class ShareLinkOut(ORM):
    id: uuid.UUID
    document_id: uuid.UUID
    expires_at: datetime
    max_downloads: int | None
    download_count: int
    revoked_at: datetime | None
    created_by: uuid.UUID
    created_at: datetime


class ShareLinkCreated(ShareLinkOut):
    token: str  # shown exactly once; only its SHA-256 is stored


class AuditOut(ORM):
    id: int
    org_id: uuid.UUID
    user_id: uuid.UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    ip: str | None
    user_agent: str | None
    request_id: str | None
    timestamp: datetime
    details: dict[str, object]


class AuditPage(BaseModel):
    items: list[AuditOut]
    total: int
    limit: int
    offset: int
