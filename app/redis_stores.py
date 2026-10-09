"""Redis-backed state: refresh-token allowlist with rotation, token-family revocation, rate limits."""

from __future__ import annotations

import time
from datetime import timedelta

from redis.asyncio import Redis


class TokenStore:
    def __init__(self, redis: Redis, refresh_ttl: int) -> None:
        self._r = redis
        self._ttl = refresh_ttl

    async def remember_refresh(self, jti: str, fam: str, user_id: str) -> None:
        await self._r.set(f"refresh:{jti}", f"{fam}:{user_id}", ex=self._ttl)

    async def consume_refresh(self, jti: str) -> bool:
        """Atomically delete the jti. False means unknown/already used (replay)."""
        return (await self._r.getdel(f"refresh:{jti}")) is not None

    async def revoke_family(self, fam: str) -> None:
        await self._r.set(f"revoked_fam:{fam}", "1", ex=self._ttl)

    async def family_revoked(self, fam: str) -> bool:
        return bool(await self._r.exists(f"revoked_fam:{fam}"))


class RateLimiter:
    """Fixed-window counter. Atomic INCR + EXPIRE NX in one MULTI so a crash cannot leave a key
    without TTL."""

    def __init__(self, redis: Redis) -> None:
        self._r = redis

    async def hit(self, scope: str, ident: str, limit: int, window: int) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        bucket = int(time.time() // window)
        key = f"rl:{scope}:{ident}:{bucket}"
        async with self._r.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, window + 1, nx=True)
            count, _ = await pipe.execute()
        retry = window - int(time.time() % window)
        return count <= limit, retry

    async def failures(self, key: str) -> int:
        val = await self._r.get(f"fail:{key}")
        return int(val) if val else 0

    async def add_failure(self, key: str, ttl: timedelta | int) -> int:
        seconds = int(ttl.total_seconds()) if isinstance(ttl, timedelta) else ttl
        async with self._r.pipeline(transaction=True) as pipe:
            pipe.incr(f"fail:{key}")
            pipe.expire(f"fail:{key}", seconds, nx=True)
            count, _ = await pipe.execute()
        return int(count)

    async def clear_failures(self, key: str) -> None:
        await self._r.delete(f"fail:{key}")
