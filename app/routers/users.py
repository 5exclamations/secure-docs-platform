from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app import audit
from app.deps import DB, AdminUser, CurrentUser
from app.models import Organization, Role, User
from app.schemas import OrgOut, UserCreate, UserOut, UserUpdate
from app.security import PasswordPolicyError, hash_password, validate_password

router = APIRouter(tags=["users"])


@router.get("/users/me", response_model=UserOut)
async def me(user: CurrentUser) -> User:
    return user


@router.get("/orgs/me", response_model=OrgOut)
async def my_org(db: DB, user: CurrentUser) -> Organization:
    return (await db.execute(select(Organization).where(Organization.id == user.org_id))).scalar_one()


@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: DB, admin: AdminUser, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)
) -> list[User]:
    stmt = (
        select(User).where(User.org_id == admin.org_id).order_by(User.created_at, User.id).limit(limit).offset(offset)
    )
    return list((await db.execute(stmt)).scalars())


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(body: UserCreate, request: Request, db: DB, admin: AdminUser) -> User:
    try:
        validate_password(body.password, body.email)
    except PasswordPolicyError as exc:
        raise HTTPException(422, str(exc)) from None
    user = User(
        org_id=admin.org_id,
        email=body.email.lower(),
        full_name=body.full_name,
        hashed_password=await asyncio.to_thread(hash_password, body.password),
        role=body.role,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Email already in use") from None
    await audit.record(
        db,
        request,
        org_id=admin.org_id,
        user_id=admin.id,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        details={"role": body.role},
    )
    await db.commit()
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(user_id: uuid.UUID, body: UserUpdate, request: Request, db: DB, admin: AdminUser) -> User:
    target = (
        await db.execute(select(User).where(User.id == user_id, User.org_id == admin.org_id).with_for_update())
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(404, "User not found")
    changes: dict[str, object] = {}
    new_role = body.role if body.role is not None else target.role
    new_active = body.is_active if body.is_active is not None else target.is_active
    if target.role == Role.ADMIN and (new_role != Role.ADMIN or not new_active):
        admins = (
            await db.execute(
                select(func.count())
                .select_from(User)
                .where(
                    User.org_id == admin.org_id,
                    User.role == Role.ADMIN.value,
                    User.is_active.is_(True),
                )
            )
        ).scalar_one()
        if admins <= 1:
            raise HTTPException(409, "Cannot remove the last active admin of the organization")
    if body.role is not None and body.role != target.role:
        changes["role"] = {"from": target.role, "to": body.role}
        target.role = body.role
    if body.is_active is not None and body.is_active != target.is_active:
        changes["is_active"] = body.is_active
        target.is_active = body.is_active
    if changes:
        await audit.record(
            db,
            request,
            org_id=admin.org_id,
            user_id=admin.id,
            action="user.update",
            resource_type="user",
            resource_id=target.id,
            details=changes,
        )
    await db.commit()
    return target
