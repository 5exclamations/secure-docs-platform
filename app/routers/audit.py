from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.deps import DB, AdminUser
from app.models import AuditLog
from app.schemas import AuditOut, AuditPage

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditPage, summary="Query the organization's audit trail (admin only)")
async def list_audit(
    db: DB,
    admin: AdminUser,
    action: str | None = Query(None, max_length=64),
    user_id: uuid.UUID | None = None,
    resource_type: str | None = Query(None, max_length=32),
    resource_id: str | None = Query(None, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AuditPage:
    conds = [AuditLog.org_id == admin.org_id]
    if action:
        conds.append(AuditLog.action == action)
    if user_id:
        conds.append(AuditLog.user_id == user_id)
    if resource_type:
        conds.append(AuditLog.resource_type == resource_type)
    if resource_id:
        conds.append(AuditLog.resource_id == resource_id)
    if since:
        conds.append(AuditLog.timestamp >= since)
    if until:
        conds.append(AuditLog.timestamp <= until)
    total = (await db.execute(select(func.count()).select_from(AuditLog).where(*conds))).scalar_one()
    rows = (
        await db.execute(select(AuditLog).where(*conds).order_by(AuditLog.id.desc()).limit(limit).offset(offset))
    ).scalars()
    return AuditPage(items=[AuditOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)
