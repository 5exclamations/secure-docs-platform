"""Against a real object store (MinIO in compose): a signed download URL works, a tampered or
unsigned one is refused, and the URL stops working once its lifetime (PRESIGN_TTL_SECONDS, default
60s) has passed."""

from __future__ import annotations

import argparse
import secrets
import sys
import time

import httpx

PASSWORD = "correct-horse-battery-9"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--ttl", type=int, default=60, help="PRESIGN_TTL_SECONDS configured on the API")
    args = ap.parse_args()
    c = httpx.Client(base_url=args.base_url, timeout=30)
    run = secrets.token_hex(3)
    email = f"admin@expiry-{run}.example.com"
    c.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Expiry",
            "organization_slug": f"expiry-{run}",
            "email": email,
            "password": PASSWORD,
        },
    ).raise_for_status()
    token = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    doc = c.post(
        "/api/v1/documents", headers=h, files={"file": ("a.pdf", b"%PDF-1.4 expiry", "application/pdf")}
    ).json()
    url = c.get(f"/api/v1/documents/{doc['id']}/download", headers=h).json()["url"]
    checks = {
        "signed URL works": httpx.get(url).status_code == 200,
        "tampered signature refused": httpx.get(url.replace("X-Amz-Signature=", "X-Amz-Signature=0")).status_code
        == 403,
        "unsigned URL refused": httpx.get(url.split("?")[0]).status_code == 403,
    }
    print(f"waiting {args.ttl + 2}s for the URL to expire...")
    time.sleep(args.ttl + 2)
    checks["expired URL refused"] = httpx.get(url).status_code == 403
    for name, ok in checks.items():
        print(f"  [{'ok' if ok else 'FAIL'}] {name}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
