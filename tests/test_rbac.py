"""Role and resource-level permission checks inside one organization."""

import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from tests.conftest import PDF, upload


async def test_viewer_cannot_upload_or_manage_users(client, new_org):
    org = await new_org()
    viewer = await org.add_user("viewer")
    assert (await upload(client, viewer)).status_code == 403
    assert (await client.get("/api/v1/users", headers=viewer.h)).status_code == 403
    assert (await client.get("/api/v1/audit", headers=viewer.h)).status_code == 403
    assert (
        await client.post("/api/v1/users", headers=viewer.h, json={"email": "a@b.co", "password": "x" * 14})
    ).status_code == 403


async def test_editor_cannot_touch_unshared_documents_of_others(client, new_org):
    org = await new_org()
    e1, e2 = await org.add_user("editor"), await org.add_user("editor")
    doc = (await upload(client, e1)).json()
    for method, path in [("GET", ""), ("GET", "/download"), ("GET", "/versions"), ("DELETE", "")]:
        r = await client.request(method, f"/api/v1/documents/{doc['id']}{path}", headers=e2.h)
        assert r.status_code == 404, (method, path)
    assert (await client.get("/api/v1/documents", headers=e2.h)).json()["total"] == 0
    denied = (await client.get("/api/v1/audit", headers=org.admin.h, params={"action": "authz.denied"})).json()
    assert denied["total"] >= 4  # every refused attempt is on record


async def test_read_grant_allows_read_but_not_write_or_share(client, new_org):
    org = await new_org()
    owner, other = await org.add_user("editor"), await org.add_user("editor")
    doc = (await upload(client, owner)).json()
    g = await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=owner.h,
        json={"user_id": other.id, "level": "read"},
    )
    assert g.status_code == 201
    assert (await client.get(f"/api/v1/documents/{doc['id']}/download", headers=other.h)).status_code == 200
    assert (await client.get("/api/v1/documents", headers=other.h)).json()["total"] == 1
    assert (
        await client.patch(f"/api/v1/documents/{doc['id']}", headers=other.h, json={"title": "x"})
    ).status_code == 403
    assert (
        await client.put(
            f"/api/v1/documents/{doc['id']}",
            headers=other.h,
            files={"file": ("a.pdf", PDF, "application/pdf")},
        )
    ).status_code == 403
    assert (await client.delete(f"/api/v1/documents/{doc['id']}", headers=other.h)).status_code == 403
    assert (
        await client.post(f"/api/v1/documents/{doc['id']}/share-links", headers=other.h, json={})
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/documents/{doc['id']}/permissions",
            headers=other.h,
            json={"user_id": owner.id, "level": "write"},
        )
    ).status_code == 403


async def test_write_grant_allows_new_version_but_not_delete(client, new_org):
    org = await new_org()
    owner, other = await org.add_user("editor"), await org.add_user("editor")
    doc = (await upload(client, owner)).json()
    await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=owner.h,
        json={"user_id": other.id, "level": "write"},
    )
    r = await client.put(
        f"/api/v1/documents/{doc['id']}",
        headers=other.h,
        files={"file": ("a.pdf", PDF + b"2", "application/pdf")},
    )
    assert r.status_code == 200 and r.json()["current_version"] == 2
    assert (await client.delete(f"/api/v1/documents/{doc['id']}", headers=other.h)).status_code == 403


async def test_viewer_role_caps_a_write_grant(client, new_org):
    org = await new_org()
    owner, viewer = await org.add_user("editor"), await org.add_user("viewer")
    doc = (await upload(client, owner)).json()
    await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=owner.h,
        json={"user_id": viewer.id, "level": "write"},
    )
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=viewer.h)).json()["my_access"] == ["read"]
    r = await client.put(
        f"/api/v1/documents/{doc['id']}",
        headers=viewer.h,
        files={"file": ("a.pdf", PDF, "application/pdf")},
    )
    assert r.status_code == 403


async def test_expired_permission_denies_access(client, new_org, owner_engine):
    org = await new_org()
    owner, other = await org.add_user("editor"), await org.add_user("editor")
    doc = (await upload(client, owner)).json()
    soon = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    r = await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=owner.h,
        json={"user_id": other.id, "level": "read", "expires_at": soon},
    )
    assert r.status_code == 201
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=other.h)).status_code == 200
    async with owner_engine.begin() as c:  # time passes
        await c.execute(
            text("UPDATE document_permissions SET expires_at = now() - interval '1 second' WHERE document_id=:d"),
            {"d": doc["id"]},
        )
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=other.h)).status_code == 404
    assert (await client.get(f"/api/v1/documents/{doc['id']}/download", headers=other.h)).status_code == 404
    assert (await client.get("/api/v1/documents", headers=other.h)).json()["total"] == 0


async def test_past_expiry_rejected_on_grant(client, new_org):
    org = await new_org()
    owner, other = await org.add_user("editor"), await org.add_user("viewer")
    doc = (await upload(client, owner)).json()
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    r = await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=owner.h,
        json={"user_id": other.id, "level": "read", "expires_at": past},
    )
    assert r.status_code == 422
    naive = await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=owner.h,
        json={"user_id": other.id, "level": "read", "expires_at": "2099-01-01T00:00:00"},
    )
    assert naive.status_code == 422


async def test_revoking_permission_takes_effect_immediately(client, new_org):
    org = await new_org()
    owner, other = await org.add_user("editor"), await org.add_user("viewer")
    doc = (await upload(client, owner)).json()
    await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=owner.h,
        json={"user_id": other.id, "level": "read"},
    )
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=other.h)).status_code == 200
    assert (
        await client.delete(f"/api/v1/documents/{doc['id']}/permissions/{other.id}", headers=owner.h)
    ).status_code == 204
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=other.h)).status_code == 404
    assert (
        await client.delete(f"/api/v1/documents/{doc['id']}/permissions/{other.id}", headers=owner.h)
    ).status_code == 404


async def test_admin_sees_all_documents_in_org(client, new_org):
    org = await new_org()
    e = await org.add_user("editor")
    doc = (await upload(client, e)).json()
    assert (await client.get(f"/api/v1/documents/{doc['id']}/download", headers=org.admin.h)).status_code == 200
    assert (await client.get("/api/v1/documents", headers=org.admin.h)).json()["total"] == 1


async def test_demoted_owner_loses_write(client, new_org):
    org = await new_org()
    e = await org.add_user("editor")
    doc = (await upload(client, e)).json()
    await client.patch(f"/api/v1/users/{e.id}", headers=org.admin.h, json={"role": "viewer"})
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=e.h)).status_code == 200
    assert (await client.patch(f"/api/v1/documents/{doc['id']}", headers=e.h, json={"title": "n"})).status_code == 403


async def test_cannot_remove_last_admin(client, new_org):
    org = await new_org()
    r = await client.patch(f"/api/v1/users/{org.admin.id}", headers=org.admin.h, json={"role": "viewer"})
    assert r.status_code == 409
    r = await client.patch(f"/api/v1/users/{org.admin.id}", headers=org.admin.h, json={"is_active": False})
    assert r.status_code == 409
    second = await org.add_user("admin")
    r = await client.patch(f"/api/v1/users/{second.id}", headers=org.admin.h, json={"role": "editor"})
    assert r.status_code == 200


async def test_role_change_is_audited_and_effective_immediately(client, new_org):
    org = await new_org()
    e = await org.add_user("editor")
    await client.patch(f"/api/v1/users/{e.id}", headers=org.admin.h, json={"role": "viewer"})
    assert (await upload(client, e)).status_code == 403
    items = (await client.get("/api/v1/audit", headers=org.admin.h, params={"action": "user.update"})).json()["items"]
    assert items[0]["details"]["role"] == {"from": "editor", "to": "viewer"}


async def test_concurrent_permission_grants_are_idempotent(client, new_org):
    org = await new_org()
    owner, other = await org.add_user("editor"), await org.add_user("viewer")
    doc = (await upload(client, owner)).json()
    rs = await asyncio.gather(
        *[
            client.post(
                f"/api/v1/documents/{doc['id']}/permissions",
                headers=owner.h,
                json={"user_id": other.id, "level": "read" if i % 2 else "write"},
            )
            for i in range(10)
        ]
    )
    assert all(r.status_code == 201 for r in rs)
    perms = (await client.get(f"/api/v1/documents/{doc['id']}/permissions", headers=owner.h)).json()
    assert len(perms) == 1
