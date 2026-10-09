"""End-to-end walkthrough of the platform against a running API.

    python scripts/demo.py --base-url http://localhost:8000

Creates two organizations, shares a document, demonstrates tenant isolation, expiring share links,
refresh-token theft detection and the audit trail. Uses only the public HTTP API.
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
import time
from typing import Any

import httpx

PASSWORD = "correct-horse-battery-9"
PDF = b"%PDF-1.4\n% demo contract\n" + b"Confidential merger terms.\n" * 40


class Demo:
    def __init__(self, base_url: str) -> None:
        self.c = httpx.Client(base_url=base_url, timeout=30)
        self.failures = 0

    def step(self, title: str) -> None:
        print(f"\n== {title}")

    def show(self, label: str, resp: httpx.Response, expect: int) -> httpx.Response:
        ok = resp.status_code == expect
        self.failures += 0 if ok else 1
        mark = "ok  " if ok else "FAIL"
        print(f"  [{mark}] {label:<58} -> {resp.status_code}")
        return resp

    def call(self, method: str, url: str, **kw: Any) -> httpx.Response:
        while True:  # auth endpoints are rate limited per IP: wait out a 429 instead of failing
            r = self.c.request(method, url, **kw)
            if r.status_code == 429 and url.startswith("/api/v1/auth"):
                wait = int(r.headers.get("retry-after", "5")) + 1
                print(f"  (rate limited, waiting {wait}s)")
                time.sleep(wait)
                continue
            return r

    def login(self, email: str) -> dict[str, str]:
        r = self.call("POST", "/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        r.raise_for_status()
        return r.json()  # type: ignore[no-any-return]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000")
    args = ap.parse_args()
    d = Demo(args.base_url)
    run = secrets.token_hex(3)

    d.step("1. Two organizations register; each gets an isolated tenant and an admin")
    users: dict[str, dict[str, Any]] = {}
    for org in ("acme", "globex"):
        email = f"admin@{org}-{run}.example.com"
        r = d.show(
            f"register {org}",
            d.call(
                "POST",
                "/api/v1/auth/register",
                json={
                    "organization_name": org.title(),
                    "organization_slug": f"{org}-{run}",
                    "email": email,
                    "password": PASSWORD,
                },
            ),
            201,
        )
        users[org] = {"email": email, "org_id": r.json()["org_id"], "token": d.login(email)["access_token"]}
    acme_h = {"Authorization": f"Bearer {users['acme']['token']}"}
    globex_h = {"Authorization": f"Bearer {users['globex']['token']}"}

    d.step("2. Acme's admin invites an editor and a viewer")
    people: dict[str, dict[str, str]] = {}
    for role in ("editor", "viewer"):
        email = f"{role}@acme-{run}.example.com"
        r = d.show(
            f"create {role}",
            d.call("POST", "/api/v1/users", headers=acme_h, json={"email": email, "password": PASSWORD, "role": role}),
            201,
        )
        tok = d.login(email)
        people[role] = {"id": r.json()["id"], "h": f"Bearer {tok['access_token']}", "refresh": tok["refresh_token"]}
    editor_h = {"Authorization": people["editor"]["h"]}
    viewer_h = {"Authorization": people["viewer"]["h"]}

    d.step("3. Editor uploads a contract, then a second version")
    r = d.show(
        "upload v1 (multipart, PDF)",
        d.call(
            "POST",
            "/api/v1/documents",
            headers=editor_h,
            files={"file": ("contract.pdf", PDF, "application/pdf")},
            data={"title": "Acme merger contract", "tags": "legal,confidential"},
        ),
        201,
    )
    doc = r.json()
    d.show(
        "upload v2",
        d.call(
            "PUT",
            f"/api/v1/documents/{doc['id']}",
            headers=editor_h,
            files={"file": ("contract-v2.pdf", PDF + b"amended", "application/pdf")},
        ),
        200,
    )
    versions = d.call("GET", f"/api/v1/documents/{doc['id']}/versions", headers=editor_h).json()
    print(f"  versions: {[v['version'] for v in versions]}")
    d.show(
        "full-text search 'merger'", d.call("GET", "/api/v1/documents", headers=editor_h, params={"q": "merger"}), 200
    )

    d.step("4. Resource-level sharing with expiry")
    d.show("viewer sees nothing before sharing", d.call("GET", f"/api/v1/documents/{doc['id']}", headers=viewer_h), 404)
    d.show(
        "editor grants viewer read access (1 hour)",
        d.call(
            "POST",
            f"/api/v1/documents/{doc['id']}/permissions",
            headers=editor_h,
            json={
                "user_id": people["viewer"]["id"],
                "level": "read",
                "expires_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() + 3600)),
            },
        ),
        201,
    )
    dl = d.show(
        "viewer requests a signed download URL",
        d.call("GET", f"/api/v1/documents/{doc['id']}/download", headers=viewer_h),
        200,
    ).json()
    body = httpx.get(dl["url"], timeout=30)
    digest_ok = hashlib.sha256(body.content).hexdigest() == dl["sha256"]
    print(f"  fetched {len(body.content)} bytes straight from object storage, sha256 matches: {digest_ok}")
    d.failures += 0 if digest_ok else 1
    d.show(
        "viewer tries to upload a new version",
        d.call(
            "PUT", f"/api/v1/documents/{doc['id']}", headers=viewer_h, files={"file": ("x.pdf", PDF, "application/pdf")}
        ),
        403,
    )

    d.step("5. Tenant isolation: Globex's admin attacks Acme's document")
    for label, method, path in [
        ("read metadata", "GET", ""),
        ("download", "GET", "/download"),
        ("list versions", "GET", "/versions"),
        ("delete", "DELETE", ""),
    ]:
        d.show(f"globex admin: {label}", d.call(method, f"/api/v1/documents/{doc['id']}{path}", headers=globex_h), 404)
    listed = d.call("GET", "/api/v1/documents", headers=globex_h, params={"q": "merger"}).json()
    print(f"  globex search for 'merger' returns {listed['total']} documents")
    d.failures += 0 if listed["total"] == 0 else 1

    d.step("6. Expiring, download-limited public share link")
    link = d.show(
        "editor creates link (max 2 downloads)",
        d.call(
            "POST",
            f"/api/v1/documents/{doc['id']}/share-links",
            headers=editor_h,
            json={"expires_in_seconds": 3600, "max_downloads": 2},
        ),
        201,
    ).json()
    for i, expected in enumerate((200, 200, 410), 1):
        d.show(f"anonymous download #{i}", d.call("POST", f"/api/v1/shared/{link['token']}/download"), expected)

    d.step("7. Refresh token rotation and theft detection")
    first = people["viewer"]["refresh"]
    rotated = d.show(
        "viewer refreshes (rotation)", d.call("POST", "/api/v1/auth/refresh", json={"refresh_token": first}), 200
    ).json()
    d.show(
        "replay of the old refresh token", d.call("POST", "/api/v1/auth/refresh", json={"refresh_token": first}), 401
    )
    d.show(
        "rotated token is now revoked too (family kill)",
        d.call("POST", "/api/v1/auth/refresh", json={"refresh_token": rotated["refresh_token"]}),
        401,
    )

    d.step("8. Audit trail (admin only, organization scoped)")
    d.show("editor cannot read the audit log", d.call("GET", "/api/v1/audit", headers=editor_h), 403)
    audit = d.show(
        "acme admin reads the audit log", d.call("GET", "/api/v1/audit", headers=acme_h, params={"limit": 200}), 200
    ).json()
    counts: dict[str, int] = {}
    for item in audit["items"]:
        counts[item["action"]] = counts.get(item["action"], 0) + 1
    for action, n in sorted(counts.items()):
        print(f"  {action:<30} x{n}")
    foreign = [i for i in audit["items"] if i["org_id"] != users["acme"]["org_id"]]
    d.failures += 1 if foreign else 0
    print(f"  entries belonging to another tenant: {len(foreign)}")

    print(f"\n{'ALL CHECKS PASSED' if d.failures == 0 else str(d.failures) + ' CHECK(S) FAILED'}")
    return 1 if d.failures else 0


if __name__ == "__main__":
    sys.exit(main())
