from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import structlog
from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from sqlalchemy import ColumnElement, and_, delete, exists, func, literal_column, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app.authz import Action, authorize, load_document
from app.deps import DB, CurrentUser, EditorUser
from app.models import Document, DocumentPermission, DocumentVersion, Role, ShareLink, User
from app.schemas import (
    DocumentDetail,
    DocumentOut,
    DocumentPage,
    DocumentUpdate,
    DownloadOut,
    PermissionIn,
    PermissionOut,
    ShareLinkCreated,
    ShareLinkIn,
    ShareLinkOut,
    VersionOut,
    parse_tags,
)
from app.security import sha256_hex
from app.uploads import StoredUpload, read_upload

router = APIRouter(prefix="/documents", tags=["documents"])
log = structlog.get_logger()

_TSVECTOR = func.to_tsvector(
    literal_column("'english'::regconfig"),
    Document.title + literal_column("' '") + func.coalesce(Document.description, ""),
)


def _visible_to(user: User) -> ColumnElement[bool]:
    base = and_(Document.org_id == user.org_id, Document.deleted_at.is_(None))
    if user.role == Role.ADMIN:
        return base
    granted = exists().where(
        DocumentPermission.document_id == Document.id,
        DocumentPermission.user_id == user.id,
        or_(DocumentPermission.expires_at.is_(None), DocumentPermission.expires_at > func.now()),
    )
    return and_(base, or_(Document.owner_id == user.id, granted))


async def _put_new_version(
    request: Request, db: AsyncSession, user: User, doc: Document, upload: StoredUpload
) -> DocumentVersion:
    """Upload the bytes first (key is random, independent of the version number), then allocate
    the version number under a row lock so concurrent uploads get distinct, gap-free numbers."""
    state = request.app.state
    version_id = uuid.uuid4()
    key = f"{doc.org_id}/{doc.id}/{version_id}"
    await state.store.put(key, upload.file, upload.content_type, upload.sha256)
    try:
        # refresh under the row lock: the cached ORM instance may carry a stale current_version
        await db.refresh(doc, with_for_update=True)
        doc.current_version += 1
        version = DocumentVersion(
            id=version_id,
            org_id=doc.org_id,
            document_id=doc.id,
            version=doc.current_version,
            s3_key=key,
            original_filename=upload.filename,
            content_type=upload.content_type,
            size_bytes=upload.size,
            checksum_sha256=upload.sha256,
            uploaded_by=user.id,
        )
        db.add(version)
        await db.flush()
        return version
    except BaseException:
        await state.store.delete(key)
        raise


def _presign(request: Request, v: DocumentVersion) -> DownloadOut:
    ttl = request.app.state.settings.presign_ttl_seconds
    url = request.app.state.store.presign_get(v.s3_key, v.original_filename, v.content_type, ttl)
    return DownloadOut(
        url=url,
        expires_at=datetime.now(UTC) + timedelta(seconds=ttl),
        filename=v.original_filename,
        sha256=v.checksum_sha256,
        version=v.version,
    )


async def _version(db: AsyncSession, doc: Document, number: int | None = None) -> DocumentVersion:
    stmt = select(DocumentVersion).where(
        DocumentVersion.document_id == doc.id,
        DocumentVersion.org_id == doc.org_id,
        DocumentVersion.version == (number if number is not None else doc.current_version),
    )
    v = (await db.execute(stmt)).scalar_one_or_none()
    if v is None:
        raise HTTPException(404, "Version not found")
    return v


@router.post("", response_model=DocumentDetail, status_code=201, summary="Upload a new document (version 1)")
async def create_document(
    request: Request,
    db: DB,
    user: EditorUser,
    file: Annotated[UploadFile, File()],
    title: Annotated[str | None, Form(min_length=1, max_length=255)] = None,
    description: Annotated[str | None, Form(max_length=5000)] = None,
    tags: Annotated[str | None, Form(max_length=1500)] = None,
) -> DocumentDetail:
    try:
        tag_list = parse_tags(tags)
    except ValueError:
        raise HTTPException(422, "Invalid tags: max 20, each up to 50 chars of [\\w .:+-]") from None
    upload = await read_upload(file, request.app.state.settings.max_upload_bytes)
    try:
        doc = Document(
            org_id=user.org_id,
            owner_id=user.id,
            title=title or upload.filename,
            description=description,
            tags=tag_list,
            current_version=0,
        )
        db.add(doc)
        await db.flush()
        version = await _put_new_version(request, db, user, doc, upload)
        await audit.record(
            db,
            request,
            org_id=user.org_id,
            user_id=user.id,
            action="document.create",
            resource_type="document",
            resource_id=doc.id,
            details={"size": upload.size, "sha256": upload.sha256, "version": 1},
        )
        await db.commit()
    finally:
        upload.file.close()
    request.app.state.metrics.documents.labels("upload").inc()
    await db.refresh(doc)
    return DocumentDetail.model_validate(doc).model_copy(
        update={"latest": VersionOut.model_validate(version), "my_access": sorted(Action)}
    )


@router.get("", response_model=DocumentPage, summary="List and search documents you can access")
async def list_documents(
    db: DB,
    user: CurrentUser,
    q: str | None = Query(None, max_length=200, description="Full-text search over title and description"),
    tag: str | None = Query(None, max_length=50),
    owner_id: uuid.UUID | None = None,
    content_type: str | None = Query(None, max_length=127),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> DocumentPage:
    conds: list[ColumnElement[bool]] = [_visible_to(user)]
    if q:
        conds.append(_TSVECTOR.op("@@")(func.plainto_tsquery(literal_column("'english'::regconfig"), q)))
    if tag:
        conds.append(Document.tags.contains([tag]))
    if owner_id:
        conds.append(Document.owner_id == owner_id)
    if content_type:
        conds.append(
            exists().where(
                DocumentVersion.document_id == Document.id,
                DocumentVersion.version == Document.current_version,
                DocumentVersion.content_type == content_type,
            )
        )
    total = (await db.execute(select(func.count()).select_from(Document).where(*conds))).scalar_one()
    rows = (
        await db.execute(
            select(Document).where(*conds).order_by(Document.created_at.desc(), Document.id).limit(limit).offset(offset)
        )
    ).scalars()
    return DocumentPage(items=[DocumentOut.model_validate(d) for d in rows], total=total, limit=limit, offset=offset)


@router.get("/{doc_id}", response_model=DocumentDetail)
async def get_document(doc_id: uuid.UUID, db: DB, user: CurrentUser, request: Request) -> DocumentDetail:
    doc = await authorize(db, request, user, doc_id, Action.READ)
    _, actions = await load_document(db, user, doc_id)
    latest = await _version(db, doc) if doc.current_version else None
    return DocumentDetail.model_validate(doc).model_copy(
        update={
            "latest": VersionOut.model_validate(latest) if latest else None,
            "my_access": sorted(a.value for a in actions),
        }
    )


@router.patch("/{doc_id}", response_model=DocumentOut, summary="Update metadata")
async def update_metadata(
    doc_id: uuid.UUID, body: DocumentUpdate, db: DB, user: CurrentUser, request: Request
) -> Document:
    doc = await authorize(db, request, user, doc_id, Action.WRITE)
    changed = body.model_dump(exclude_unset=True)
    for field, value in changed.items():
        setattr(doc, field, value)
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action="document.update",
        resource_type="document",
        resource_id=doc.id,
        details={"fields": sorted(changed)},
    )
    await db.commit()
    await db.refresh(doc)
    return doc


@router.put("/{doc_id}", response_model=DocumentDetail, summary="Upload a new version")
async def upload_version(
    doc_id: uuid.UUID,
    request: Request,
    db: DB,
    user: CurrentUser,
    file: Annotated[UploadFile, File()],
) -> DocumentDetail:
    doc = await authorize(db, request, user, doc_id, Action.WRITE)
    upload = await read_upload(file, request.app.state.settings.max_upload_bytes)
    try:
        version = await _put_new_version(request, db, user, doc, upload)
        await audit.record(
            db,
            request,
            org_id=user.org_id,
            user_id=user.id,
            action="document.version_create",
            resource_type="document",
            resource_id=doc.id,
            details={"version": version.version, "size": upload.size, "sha256": upload.sha256},
        )
        await db.commit()
    finally:
        upload.file.close()
    request.app.state.metrics.documents.labels("new_version").inc()
    await db.refresh(doc)
    return DocumentDetail.model_validate(doc).model_copy(update={"latest": VersionOut.model_validate(version)})


@router.delete("/{doc_id}", status_code=204, summary="Soft delete; admins may hard delete with ?hard=true")
async def delete_document(doc_id: uuid.UUID, request: Request, db: DB, user: CurrentUser, hard: bool = False) -> None:
    if hard:
        if user.role != Role.ADMIN:
            raise HTTPException(403, "Only admins can hard delete")
        doc = await authorize(db, request, user, doc_id, Action.DELETE, include_deleted=True)
        keys = (
            (await db.execute(select(DocumentVersion.s3_key).where(DocumentVersion.document_id == doc.id)))
            .scalars()
            .all()
        )
        for key in keys:  # objects first: if S3 fails we keep the rows and the request errors
            await request.app.state.store.delete(key)
        await db.execute(delete(Document).where(Document.id == doc.id, Document.org_id == user.org_id))
        action = "document.hard_delete"
    else:
        doc = await authorize(db, request, user, doc_id, Action.DELETE)
        doc.deleted_at = datetime.now(UTC)
        action = "document.delete"
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action=action,
        resource_type="document",
        resource_id=doc_id,
    )
    await db.commit()
    request.app.state.metrics.documents.labels("delete").inc()


@router.get(
    "/{doc_id}/download",
    response_model=DownloadOut,
    summary="Short-lived signed URL for the latest version",
)
async def download(doc_id: uuid.UUID, request: Request, db: DB, user: CurrentUser) -> DownloadOut:
    doc = await authorize(db, request, user, doc_id, Action.READ)
    out = _presign(request, await _version(db, doc))
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action="document.download",
        resource_type="document",
        resource_id=doc.id,
        details={"version": out.version},
    )
    await db.commit()
    request.app.state.metrics.documents.labels("download").inc()
    return out


@router.get("/{doc_id}/versions", response_model=list[VersionOut])
async def list_versions(doc_id: uuid.UUID, request: Request, db: DB, user: CurrentUser) -> list[DocumentVersion]:
    doc = await authorize(db, request, user, doc_id, Action.READ)
    rows = await db.execute(
        select(DocumentVersion)
        .where(DocumentVersion.document_id == doc.id, DocumentVersion.org_id == doc.org_id)
        .order_by(DocumentVersion.version.desc())
    )
    return list(rows.scalars())


@router.get("/{doc_id}/versions/{version}/download", response_model=DownloadOut)
async def download_version(doc_id: uuid.UUID, version: int, request: Request, db: DB, user: CurrentUser) -> DownloadOut:
    doc = await authorize(db, request, user, doc_id, Action.READ)
    out = _presign(request, await _version(db, doc, version))
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action="document.version_download",
        resource_type="document",
        resource_id=doc.id,
        details={"version": version},
    )
    await db.commit()
    request.app.state.metrics.documents.labels("download").inc()
    return out


# ---- per-user permissions -------------------------------------------------------------------


@router.get("/{doc_id}/permissions", response_model=list[PermissionOut])
async def list_permissions(doc_id: uuid.UUID, request: Request, db: DB, user: CurrentUser) -> list[DocumentPermission]:
    doc = await authorize(db, request, user, doc_id, Action.SHARE)
    rows = await db.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == doc.id, DocumentPermission.org_id == user.org_id
        )
    )
    return list(rows.scalars())


@router.post("/{doc_id}/permissions", response_model=PermissionOut, status_code=201)
async def grant_permission(
    doc_id: uuid.UUID, body: PermissionIn, request: Request, db: DB, user: CurrentUser
) -> DocumentPermission:
    doc = await authorize(db, request, user, doc_id, Action.SHARE)
    if body.expires_at is not None and body.expires_at <= datetime.now(UTC):
        raise HTTPException(422, "expires_at must be in the future")
    target = (
        await db.execute(select(User).where(User.id == body.user_id, User.org_id == user.org_id))
    ).scalar_one_or_none()
    if target is None or not target.is_active:
        raise HTTPException(404, "User not found in your organization")
    if target.id == doc.owner_id:
        raise HTTPException(409, "The owner already has full access")
    stmt = (
        pg_insert(DocumentPermission)
        .values(
            org_id=user.org_id,
            document_id=doc.id,
            user_id=target.id,
            level=body.level,
            expires_at=body.expires_at,
            granted_by=user.id,
        )
        .on_conflict_do_update(
            constraint="uq_permissions_doc_user",
            set_={"level": body.level, "expires_at": body.expires_at, "granted_by": user.id},
        )
        .returning(DocumentPermission)
    )
    perm = (await db.execute(stmt, execution_options={"populate_existing": True})).scalar_one()
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action="permission.grant",
        resource_type="document",
        resource_id=doc.id,
        details={
            "grantee": str(target.id),
            "level": body.level,
            "expires_at": body.expires_at.isoformat() if body.expires_at else None,
        },
    )
    await db.commit()
    return perm


@router.delete("/{doc_id}/permissions/{user_id}", status_code=204)
async def revoke_permission(doc_id: uuid.UUID, user_id: uuid.UUID, request: Request, db: DB, user: CurrentUser) -> None:
    doc = await authorize(db, request, user, doc_id, Action.SHARE)
    res = await db.execute(
        delete(DocumentPermission).where(
            DocumentPermission.document_id == doc.id,
            DocumentPermission.user_id == user_id,
            DocumentPermission.org_id == user.org_id,
        )
    )
    if res.rowcount == 0:  # type: ignore[attr-defined]
        raise HTTPException(404, "Permission not found")
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action="permission.revoke",
        resource_type="document",
        resource_id=doc.id,
        details={"grantee": str(user_id)},
    )
    await db.commit()


# ---- expiring share links -------------------------------------------------------------------


@router.post(
    "/{doc_id}/share-links",
    response_model=ShareLinkCreated,
    status_code=201,
    summary="Create an expiring public download link (token is shown once)",
)
async def create_share_link(
    doc_id: uuid.UUID, body: ShareLinkIn, request: Request, db: DB, user: CurrentUser
) -> ShareLinkCreated:
    doc = await authorize(db, request, user, doc_id, Action.SHARE)
    token = f"{user.org_id.hex}.{secrets.token_urlsafe(32)}"
    link = ShareLink(
        org_id=user.org_id,
        document_id=doc.id,
        token_hash=sha256_hex(token),
        expires_at=datetime.now(UTC) + timedelta(seconds=body.expires_in_seconds),
        max_downloads=body.max_downloads,
        created_by=user.id,
    )
    db.add(link)
    await db.flush()
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action="share.create",
        resource_type="document",
        resource_id=doc.id,
        details={
            "link_id": str(link.id),
            "expires_at": link.expires_at.isoformat(),
            "max_downloads": body.max_downloads,
        },
    )
    await db.commit()
    return ShareLinkCreated(**ShareLinkOut.model_validate(link).model_dump(), token=token)


@router.get("/{doc_id}/share-links", response_model=list[ShareLinkOut])
async def list_share_links(doc_id: uuid.UUID, request: Request, db: DB, user: CurrentUser) -> list[ShareLink]:
    doc = await authorize(db, request, user, doc_id, Action.SHARE)
    rows = await db.execute(
        select(ShareLink)
        .where(ShareLink.document_id == doc.id, ShareLink.org_id == user.org_id)
        .order_by(ShareLink.created_at.desc())
    )
    return list(rows.scalars())


@router.delete("/{doc_id}/share-links/{link_id}", status_code=204)
async def revoke_share_link(doc_id: uuid.UUID, link_id: uuid.UUID, request: Request, db: DB, user: CurrentUser) -> None:
    doc = await authorize(db, request, user, doc_id, Action.SHARE)
    link = (
        await db.execute(
            select(ShareLink).where(
                ShareLink.id == link_id,
                ShareLink.document_id == doc.id,
                ShareLink.org_id == user.org_id,
            )
        )
    ).scalar_one_or_none()
    if link is None:
        raise HTTPException(404, "Share link not found")
    link.revoked_at = datetime.now(UTC)
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action="share.revoke",
        resource_type="document",
        resource_id=doc.id,
        details={"link_id": str(link.id)},
    )
    await db.commit()
