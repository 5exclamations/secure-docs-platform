from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.clientip import client_ip
from app.models import AuditLog


async def record(
    db: AsyncSession,
    request: Request,
    *,
    org_id: uuid.UUID,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: uuid.UUID | str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Stage an audit row in the caller's transaction (so the action and its audit trail commit
    or roll back together)."""
    ctx = structlog.contextvars.get_contextvars()
    db.add(
        AuditLog(
            org_id=org_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            ip=client_ip(request, request.app.state.settings.trusted_proxy_count),
            user_agent=(request.headers.get("user-agent") or "")[:256] or None,
            request_id=ctx.get("request_id"),
            details=details or {},
        )
    )
    await db.flush()
