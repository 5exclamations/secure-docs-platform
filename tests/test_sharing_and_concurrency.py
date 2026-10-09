import asyncio
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import text

from tests.conftest import PDF, next_ip, upload


async def _link(client, actor, doc_id, **body):
    r = await client.post(f"/api/v1/documents/{doc_id}/share-links", headers=actor.h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _dl(client, token):
    return client.post(f"/api/v1/shared/{token}/download", headers={"X-Forwarded-For": next_ip()})


async def test_share_link_downloads_without_login(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    link = await _link(client, org.admin, doc["id"], expires_in_seconds=600)
    r = await _dl(client, link["token"])
    assert r.status_code == 200
    async with httpx.AsyncClient() as raw:
        assert (await raw.get(r.json()["url"])).content == PDF
    # token is only revealed at creation and only its hash is stored
    listed = (await client.get(f"/api/v1/documents/{doc['id']}/share-links", headers=org.admin.h)).json()
    assert "token" not in listed[0] and listed[0]["download_count"] == 1


async def test_token_not_stored_in_plaintext(owner_engine, client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    link = await _link(client, org.admin, doc["id"])
    async with owner_engine.connect() as c:
        rows = (
            (
                await c.execute(
                    text("SELECT token_hash FROM share_links WHERE document_id=:d"),
                    {"d": doc["id"]},
                )
            )
            .scalars()
            .all()
        )
    assert rows and link["token"] not in rows[0] and len(rows[0]) == 64


async def test_expired_link_is_refused_and_audited(client, new_org, owner_engine):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    link = await _link(client, org.admin, doc["id"], expires_in_seconds=60)
    assert (await _dl(client, link["token"])).status_code == 200
    async with owner_engine.begin() as c:
        await c.execute(
            text("UPDATE share_links SET expires_at = now() - interval '1 second' WHERE id=:i"),
            {"i": link["id"]},
        )
    r = await _dl(client, link["token"])
    assert r.status_code == 410 and "expired" in r.json()["detail"]
    denied = (
        await client.get("/api/v1/audit", headers=org.admin.h, params={"action": "share.download_denied"})
    ).json()["items"]
    assert denied[0]["details"]["reason"] == "expired" and denied[0]["user_id"] is None


async def test_revoked_link_is_refused(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    link = await _link(client, org.admin, doc["id"])
    assert (
        await client.delete(f"/api/v1/documents/{doc['id']}/share-links/{link['id']}", headers=org.admin.h)
    ).status_code == 204
    r = await _dl(client, link["token"])
    assert r.status_code == 410 and "revoked" in r.json()["detail"]


async def test_garbage_and_unknown_tokens(client):
    for t in ("garbage", "zz.zz", "0" * 32 + ".nope", "a" * 300):
        assert (await _dl(client, t)).status_code == 404


async def test_deleted_document_link_does_not_work_and_burns_nothing(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    link = await _link(client, org.admin, doc["id"], max_downloads=1)
    await client.delete(f"/api/v1/documents/{doc['id']}", headers=org.admin.h)
    assert (await _dl(client, link["token"])).status_code == 404


async def test_share_link_limits_validated(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    for body in (
        {"expires_in_seconds": 5},
        {"expires_in_seconds": 10**9},
        {"max_downloads": 0},
        {"unknown": 1},
    ):
        r = await client.post(f"/api/v1/documents/{doc['id']}/share-links", headers=org.admin.h, json=body)
        assert r.status_code == 422, body


async def test_public_endpoint_is_rate_limited(client, new_org):
    ip = {"X-Forwarded-For": next_ip()}
    codes = [(await client.post("/api/v1/shared/junk/download", headers=ip)).status_code for _ in range(33)]
    assert codes[:30] == [404] * 30 and codes[30:] == [429] * 3


async def test_max_downloads_holds_under_concurrency(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    link = await _link(client, org.admin, doc["id"], max_downloads=5)
    results = await asyncio.gather(*[_dl(client, link["token"]) for _ in range(25)])
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) == 5 and codes.count(410) == 20
    listed = (await client.get(f"/api/v1/documents/{doc['id']}/share-links", headers=org.admin.h)).json()
    assert listed[0]["download_count"] == 5


async def test_concurrent_version_uploads_get_distinct_numbers(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    n = 12
    rs = await asyncio.gather(
        *[
            client.put(
                f"/api/v1/documents/{doc['id']}",
                headers=org.admin.h,
                files={"file": (f"v{i}.pdf", PDF + str(i).encode(), "application/pdf")},
            )
            for i in range(n)
        ]
    )
    assert all(r.status_code == 200 for r in rs)
    versions = (await client.get(f"/api/v1/documents/{doc['id']}/versions", headers=org.admin.h)).json()
    assert sorted(v["version"] for v in versions) == list(range(1, n + 2))
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=org.admin.h)).json()["current_version"] == n + 1


async def test_concurrent_reads_while_revoking_permission(client, new_org):
    org = await new_org()
    owner, other = await org.add_user("editor"), await org.add_user("viewer")
    doc = (await upload(client, owner)).json()
    await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=owner.h,
        json={"user_id": other.id, "level": "read"},
    )
    reads = [client.get(f"/api/v1/documents/{doc['id']}/download", headers=other.h) for _ in range(10)]
    revoke = client.delete(f"/api/v1/documents/{doc['id']}/permissions/{other.id}", headers=owner.h)
    results = await asyncio.gather(*reads, revoke)
    assert results[-1].status_code == 204
    assert {r.status_code for r in results[:-1]} <= {200, 404}
    assert (await client.get(f"/api/v1/documents/{doc['id']}/download", headers=other.h)).status_code == 404


async def test_parallel_tenants_do_not_bleed_context(client, new_org):
    """Interleaved requests from many tenants over a shared connection pool must each see only
    their own data (tenant context is transaction-local)."""
    orgs = [await new_org() for _ in range(6)]
    for i, o in enumerate(orgs):
        await upload(client, o.admin, title=f"tenant-{i}-only")

    async def check(i: int, o):
        r = await client.get("/api/v1/documents", headers=o.admin.h)
        return [d["title"] for d in r.json()["items"]] == [f"tenant-{i}-only"]

    results = await asyncio.gather(*[check(i, o) for _ in range(8) for i, o in enumerate(orgs)])
    assert all(results)


async def test_expiry_helpers_use_server_clock_not_client(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    link = await _link(client, org.admin, doc["id"], expires_in_seconds=3600)
    exp = datetime.fromisoformat(link["expires_at"])
    assert timedelta(minutes=59) < exp - datetime.now(UTC) < timedelta(minutes=61)
