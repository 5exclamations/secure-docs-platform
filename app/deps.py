"""Request dependencies: DB session, rate limiting, authentication."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

import structlog
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.clientip import client_ip
from app.config import Settings
from app.db import set_tenant
from app.models import Organization, Role, User
from app.security import TokenError

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)
_UNAUTH = {"WWW-Authenticate": "Bearer"}


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.session_factory() as session:
        yield session


DB = Annotated[AsyncSession, Depends(get_db)]


def ip_of(request: Request) -> str:
    return client_ip(request, request.app.state.settings.trusted_proxy_count)


async def enforce_limit(request: Request, scope: str, ident: str, limit: int, window: int = 60) -> None:
    try:
        allowed, retry = await request.app.state.limiter.hit(scope, ident, limit, window)
    except Exception as exc:  # Redis unavailable: fail closed, the API must not run unthrottled
        structlog.get_logger().error("rate_limiter_unavailable", error=str(exc))
        raise HTTPException(503, "Service temporarily unavailable") from exc
    if not allowed:
        request.app.state.metrics.rate_limited.labels(scope).inc()
        raise HTTPException(429, "Too many requests", headers={"Retry-After": str(retry)})


def ip_limit(scope: str, setting: str) -> Callable[[Request], Awaitable[None]]:
    """Dependency factory: per-IP limit whose value is read from settings at request time."""

    async def dep(request: Request) -> None:
        limit: int = getattr(request.app.state.settings, setting)
        await enforce_limit(request, scope, ip_of(request), limit)

    return dep


async def get_current_user(request: Request, db: DB, token: Annotated[str | None, Depends(oauth2_scheme)]) -> User:
    state = request.app.state
    if not token:
        raise HTTPException(401, "Not authenticated", headers=_UNAUTH)
    try:
        claims = state.tokens.decode(token, "access")
    except TokenError:
        raise HTTPException(401, "Invalid or expired token", headers=_UNAUTH) from None
    try:
        revoked = await state.token_store.family_revoked(claims.fam)
    except Exception as exc:
        raise HTTPException(503, "Service temporarily unavailable") from exc
    if revoked:
        raise HTTPException(401, "Session has been revoked", headers=_UNAUTH)

    user = (await db.execute(select(User).where(User.id == claims.sub))).scalar_one_or_none()
    if user is None or not user.is_active or user.org_id != claims.org_id:
        raise HTTPException(401, "Invalid or expired token", headers=_UNAUTH)
    org = (await db.execute(select(Organization).where(Organization.id == user.org_id))).scalar_one()
    if not org.is_active:
        raise HTTPException(401, "Invalid or expired token", headers=_UNAUTH)

    await set_tenant(db, user.org_id)
    structlog.contextvars.bind_contextvars(user_id=str(user.id), org_id=str(user.org_id))
    request.state.user = user
    request.state.claims = claims
    await enforce_limit(request, "user", str(user.id), state.settings.rate_limit_user_per_minute)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: Role) -> Callable[[User], Awaitable[User]]:
    allowed = {r.value for r in roles}

    async def dep(user: CurrentUser) -> User:
        if user.role not in allowed:
            raise HTTPException(403, "Insufficient role")
        return user

    return dep


AdminUser = Annotated[User, Depends(require_roles(Role.ADMIN))]
EditorUser = Annotated[User, Depends(require_roles(Role.ADMIN, Role.EDITOR))]


def parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(404, "Not found") from None
