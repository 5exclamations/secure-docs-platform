from __future__ import annotations

import asyncio
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app.db import set_tenant
from app.deps import DB, CurrentUser, enforce_limit, ip_limit, ip_of
from app.models import Organization, Role, User
from app.schemas import LoginRequest, RefreshRequest, RegisterRequest, TokenPair, UserOut
from app.security import (
    PasswordPolicyError,
    TokenError,
    hash_password,
    password_needs_rehash,
    sha256_hex,
    validate_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])
_BAD_CREDS = HTTPException(401, "Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})


async def _issue_pair(request: Request, user: User, fam: str | None = None) -> TokenPair:
    state = request.app.state
    fam = fam or secrets.token_urlsafe(16)
    access, _ = state.tokens.issue(user.id, user.org_id, "access", fam)
    refresh, claims = state.tokens.issue(user.id, user.org_id, "refresh", fam)
    await state.token_store.remember_refresh(claims.jti, fam, str(user.id))
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=state.settings.access_token_ttl_seconds,
    )


@router.post(
    "/register",
    response_model=UserOut,
    status_code=201,
    dependencies=[Depends(ip_limit("register", "rate_limit_login_per_minute"))],
    summary="Create an organization and its first admin",
)
async def register(body: RegisterRequest, request: Request, db: DB) -> User:
    try:
        validate_password(body.password, body.email)
    except PasswordPolicyError as exc:
        raise HTTPException(422, str(exc)) from None
    org = Organization(name=body.organization_name, slug=body.organization_slug)
    db.add(org)
    try:
        await db.flush()
        user = User(
            org_id=org.id,
            email=body.email.lower(),
            full_name=body.full_name,
            hashed_password=await asyncio.to_thread(hash_password, body.password),
            role=Role.ADMIN.value,
        )
        db.add(user)
        await db.flush()
        await set_tenant(db, org.id)
        await audit.record(
            db,
            request,
            org_id=org.id,
            user_id=user.id,
            action="org.register",
            resource_type="organization",
            resource_id=org.id,
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Organization slug or email already in use") from None
    return user


async def _authenticate(request: Request, db: AsyncSession, email: str, password: str) -> TokenPair:
    state = request.app.state
    s = state.settings
    email = email.lower()
    fail_key = sha256_hex(email)
    if await state.limiter.failures(fail_key) >= s.login_lockout_threshold:
        state.metrics.rate_limited.labels("login_lockout").inc()
        raise HTTPException(
            429,
            "Too many failed attempts, try again later",
            headers={"Retry-After": str(s.login_lockout_seconds)},
        )

    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    # argon2 is CPU bound: keep it off the event loop. Unknown users verify against a dummy hash.
    ok = await asyncio.to_thread(verify_password, password, user.hashed_password if user else None)
    if user is None or not ok or not user.is_active:
        await state.limiter.add_failure(fail_key, s.login_lockout_seconds)
        state.metrics.auth_events.labels("login_failed").inc()
        if user is not None:
            await set_tenant(db, user.org_id)
            await audit.record(
                db,
                request,
                org_id=user.org_id,
                user_id=user.id,
                action="auth.login_failed",
                details={"reason": "bad_credentials_or_inactive"},
            )
            await db.commit()
        raise _BAD_CREDS

    await state.limiter.clear_failures(fail_key)
    await set_tenant(db, user.org_id)
    if password_needs_rehash(user.hashed_password):
        user.hashed_password = await asyncio.to_thread(hash_password, password)
    await audit.record(db, request, org_id=user.org_id, user_id=user.id, action="auth.login")
    await db.commit()
    state.metrics.auth_events.labels("login").inc()
    return await _issue_pair(request, user)


async def _rotate(request: Request, db: AsyncSession, refresh_token: str) -> TokenPair:
    state = request.app.state
    try:
        claims = state.tokens.decode(refresh_token, "refresh")
    except TokenError:
        raise HTTPException(401, "Invalid refresh token") from None
    if not await state.token_store.consume_refresh(claims.jti):
        # A refresh token was presented twice: assume theft and kill the whole session family.
        await state.token_store.revoke_family(claims.fam)
        state.metrics.auth_events.labels("refresh_reuse").inc()
        await set_tenant(db, claims.org_id)
        await audit.record(
            db,
            request,
            org_id=claims.org_id,
            user_id=claims.sub,
            action="auth.refresh_reuse_detected",
            details={"family": claims.fam},
        )
        await db.commit()
        raise HTTPException(401, "Invalid refresh token")
    if await state.token_store.family_revoked(claims.fam):
        raise HTTPException(401, "Invalid refresh token")
    user = (await db.execute(select(User).where(User.id == claims.sub))).scalar_one_or_none()
    if user is None or not user.is_active or user.org_id != claims.org_id:
        raise HTTPException(401, "Invalid refresh token")
    await set_tenant(db, user.org_id)
    await audit.record(db, request, org_id=user.org_id, user_id=user.id, action="auth.refresh")
    await db.commit()
    return await _issue_pair(request, user, fam=claims.fam)


@router.post(
    "/login",
    response_model=TokenPair,
    dependencies=[Depends(ip_limit("login", "rate_limit_login_per_minute"))],
)
async def login(body: LoginRequest, request: Request, db: DB) -> TokenPair:
    return await _authenticate(request, db, body.email, body.password)


@router.post(
    "/refresh",
    response_model=TokenPair,
    dependencies=[Depends(ip_limit("refresh", "rate_limit_user_per_minute"))],
)
async def refresh(body: RefreshRequest, request: Request, db: DB) -> TokenPair:
    return await _rotate(request, db, body.refresh_token)


@router.post(
    "/token",
    response_model=TokenPair,
    summary="OAuth2 token endpoint (password and refresh_token grants)",
)
async def oauth_token(
    request: Request,
    db: DB,
    grant_type: Annotated[str, Form(pattern="^(password|refresh_token)$")],
    username: Annotated[str | None, Form(max_length=320)] = None,
    password: Annotated[str | None, Form(max_length=128)] = None,
    refresh_token: Annotated[str | None, Form(max_length=2048)] = None,
) -> TokenPair:
    limit = request.app.state.settings.rate_limit_login_per_minute
    await enforce_limit(request, "login", ip_of(request), limit)
    if grant_type == "password":
        if not username or not password:
            raise HTTPException(400, "username and password are required")
        return await _authenticate(request, db, username, password)
    if not refresh_token:
        raise HTTPException(400, "refresh_token is required")
    return await _rotate(request, db, refresh_token)


@router.post("/logout", status_code=204)
async def logout(request: Request, db: DB, user: CurrentUser) -> None:
    """Revokes the whole token family: the access token used here and its refresh tokens."""
    await request.app.state.token_store.revoke_family(request.state.claims.fam)
    await audit.record(db, request, org_id=user.org_id, user_id=user.id, action="auth.logout")
    await db.commit()
    request.app.state.metrics.auth_events.labels("logout").inc()
