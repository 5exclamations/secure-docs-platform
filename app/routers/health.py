from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

router = APIRouter()
ops = APIRouter(tags=["ops"])
wellknown = APIRouter(tags=["auth"])


@ops.get("/health", summary="Liveness: the process is up")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@ops.get("/health/ready", summary="Readiness: PostgreSQL, Redis and the bucket are reachable")
async def ready(request: Request) -> dict[str, object]:
    state = request.app.state
    checks: dict[str, str] = {}
    try:
        async with state.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"
    try:
        await state.redis.ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "unavailable"
    try:
        await state.store.ping()
        checks["storage"] = "ok"
    except Exception:
        checks["storage"] = "unavailable"
    healthy = all(v == "ok" for v in checks.values())
    if not healthy:
        raise HTTPException(503, detail=checks)
    return {"status": "ok", "checks": checks}


@ops.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    token = request.app.state.settings.metrics_token
    if token is not None:
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(supplied, token.get_secret_value()):
            raise HTTPException(401, "Unauthorized")
    return Response(generate_latest(request.app.state.metrics.registry), media_type=CONTENT_TYPE_LATEST)


@wellknown.get("/.well-known/jwks.json", summary="Public signing keys (RS256 only)")
async def jwks(request: Request) -> dict[str, object]:
    return request.app.state.tokens.jwks()  # type: ignore[no-any-return]


@wellknown.get("/.well-known/openid-configuration", include_in_schema=False)
async def discovery(request: Request) -> dict[str, object]:
    s = request.app.state.settings
    base = str(request.base_url).rstrip("/")
    return {
        "issuer": s.jwt_issuer,
        "token_endpoint": f"{base}/api/v1/auth/token",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "grant_types_supported": ["password", "refresh_token"],
        "id_token_signing_alg_values_supported": [s.jwt_algorithm],
        "token_endpoint_auth_methods_supported": ["none"],
    }


router.include_router(ops)
router.include_router(wellknown)
