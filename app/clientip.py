from __future__ import annotations

from starlette.requests import Request


def client_ip(request: Request, trusted_proxy_count: int) -> str:
    """Resolve the caller address. X-Forwarded-For is only honoured for the configured number of
    trusted proxies, counted from the right (the entries a proxy appended), so a client cannot
    spoof its address by sending its own header."""
    peer = request.client.host if request.client else "unknown"
    if trusted_proxy_count <= 0:
        return peer
    parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if len(parts) >= trusted_proxy_count:
        return parts[-trusted_proxy_count][:45]
    return peer
