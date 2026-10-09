"""Resource-level authorization.

Effective rights on a document = (relationship to the document) ∩ (role ceiling).

relationship: admin of the same org -> everything; owner -> everything; otherwise the active,
non-expired per-user grant (read / write).
role ceiling: admin everything; editor read/write/delete/share; viewer read only.

Cross-tenant ids and documents the caller cannot even read both answer 404 so identifiers cannot
be enumerated; a caller who can read but lacks the right gets 403.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app.models import Document, DocumentPermission, PermissionLevel, Role, User


class Action(enum.StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SHARE = "share"


_ROLE_CEILING: dict[str, set[Action]] = {
    Role.ADMIN: set(Action),
    Role.EDITOR: set(Action),
    Role.VIEWER: {Action.READ},
}


def effective_actions(user: User, doc: Document, grant: DocumentPermission | None) -> set[Action]:
    if doc.org_id != user.org_id:
        return set()
    if user.role == Role.ADMIN or doc.owner_id == user.id:
        relationship = set(Action)
    elif grant is not None and (grant.expires_at is None or grant.expires_at > datetime.now(UTC)):
        relationship = {Action.READ}
        if grant.level == PermissionLevel.WRITE:
            relationship.add(Action.WRITE)
    else:
        relationship = set()
    return relationship & _ROLE_CEILING.get(user.role, set())


async def load_document(
    db: AsyncSession, user: User, doc_id: uuid.UUID, *, include_deleted: bool = False
) -> tuple[Document, set[Action]]:
    stmt = select(Document).where(Document.id == doc_id, Document.org_id == user.org_id)
    if not include_deleted:
        stmt = stmt.where(Document.deleted_at.is_(None))
    doc = (await db.execute(stmt)).scalar_one_or_none()
    if doc is None:
        raise HTTPException(404, "Document not found")
    grant = (
        await db.execute(
            select(DocumentPermission).where(
                DocumentPermission.document_id == doc.id, DocumentPermission.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    return doc, effective_actions(user, doc, grant)


async def authorize(
    db: AsyncSession,
    request: Request,
    user: User,
    doc_id: uuid.UUID,
    action: Action,
    *,
    include_deleted: bool = False,
) -> Document:
    doc, actions = await load_document(db, user, doc_id, include_deleted=include_deleted)
    if action in actions:
        return doc
    request.app.state.metrics.authz_denied.labels(action.value).inc()
    await audit.record(
        db,
        request,
        org_id=user.org_id,
        user_id=user.id,
        action="authz.denied",
        resource_type="document",
        resource_id=doc.id,
        details={"required": action.value},
    )
    await db.commit()  # persist the denial even though the request fails
    if Action.READ not in actions:
        raise HTTPException(404, "Document not found")
    raise HTTPException(403, f"Missing '{action.value}' permission on this document")
