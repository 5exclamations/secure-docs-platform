"""Unauthenticated access through an expiring share link."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, text

from app import audit
from app.db import set_tenant
from app.deps import DB, ip_limit
from app.models import Document, DocumentVersion, Organization, ShareLink
from app.routers.documents import _presign
from app.schemas import DownloadOut
from app.security import sha256_hex

router = APIRouter(prefix="/shared", tags=["shared links"])


@router.post(
    "/{token}/download",
    response_model=DownloadOut,
    dependencies=[Depends(ip_limit("public", "rate_limit_public_per_minute"))],
    summary="Exchange a share token for a short-lived signed download URL",
)
async def shared_download(token: str, request: Request, db: DB) -> DownloadOut:
    try:
        org_id = uuid.UUID(hex=token.split(".", 1)[0])
    except ValueError:
        raise HTTPException(404, "Link not found") from None
    org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
    if org is None or not org.is_active or len(token) > 100:
        raise HTTPException(404, "Link not found")
    await set_tenant(db, org_id)
    token_hash = sha256_hex(token)

    # Single atomic statement: validity checks and the download counter cannot race, so a link
    # limited to N downloads never yields N+1 even under concurrent requests.
    row = (
        await db.execute(
            text(
                "UPDATE share_links SET download_count = download_count + 1 "
                "WHERE token_hash = :h AND org_id = :org AND revoked_at IS NULL AND expires_at > now() "
                "AND (max_downloads IS NULL OR download_count < max_downloads) "
                "RETURNING id, document_id"
            ),
            {"h": token_hash, "org": org_id},
        )
    ).first()
    if row is None:
        link = (await db.execute(select(ShareLink).where(ShareLink.token_hash == token_hash))).scalar_one_or_none()
        if link is None:
            raise HTTPException(404, "Link not found")
        now = (await db.execute(text("SELECT now()"))).scalar_one()
        reason = "revoked" if link.revoked_at else "expired" if link.expires_at <= now else "exhausted"
        await audit.record(
            db,
            request,
            org_id=org_id,
            user_id=None,
            action="share.download_denied",
            resource_type="document",
            resource_id=link.document_id,
            details={"link_id": str(link.id), "reason": reason},
        )
        await db.commit()
        request.app.state.metrics.authz_denied.labels(f"share_{reason}").inc()
        raise HTTPException(410, f"Link is {reason}")

    link_id, doc_id = row
    doc = (
        await db.execute(
            select(Document).where(Document.id == doc_id, Document.org_id == org_id, Document.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if doc is None or doc.current_version == 0:
        await db.rollback()  # do not burn a download on a deleted document
        raise HTTPException(404, "Link not found")
    version = (
        await db.execute(
            select(DocumentVersion).where(
                DocumentVersion.document_id == doc.id,
                DocumentVersion.version == doc.current_version,
            )
        )
    ).scalar_one()
    out = _presign(request, version)
    await audit.record(
        db,
        request,
        org_id=org_id,
        user_id=None,
        action="share.download",
        resource_type="document",
        resource_id=doc.id,
        details={"link_id": str(link_id), "version": version.version},
    )
    await db.commit()
    request.app.state.metrics.documents.labels("shared_download").inc()
    return out
