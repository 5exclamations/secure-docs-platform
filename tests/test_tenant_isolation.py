"""Cross-tenant attack scenarios. Each test creates two organizations; org B tries to touch org A."""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from tests.conftest import PDF, next_ip, upload


@pytest.fixture
async def two_orgs(new_org, client):
    a, b = await new_org(), await new_org()
    doc = (await upload(client, a.admin, title="Org A secret merger plan", tags="secret")).json()
    return a, b, doc


async def test_foreign_document_is_invisible_everywhere(client, two_orgs):
    a, b, doc = two_orgs
    did = doc["id"]
    attempts = [
        ("GET", f"/api/v1/documents/{did}", None),
        ("GET", f"/api/v1/documents/{did}/download", None),
        ("GET", f"/api/v1/documents/{did}/versions", None),
        ("GET", f"/api/v1/documents/{did}/versions/1/download", None),
        ("PATCH", f"/api/v1/documents/{did}", {"json": {"title": "pwned"}}),
        ("DELETE", f"/api/v1/documents/{did}", None),
        ("DELETE", f"/api/v1/documents/{did}?hard=true", None),
        ("GET", f"/api/v1/documents/{did}/permissions", None),
        ("POST", f"/api/v1/documents/{did}/share-links", {"json": {}}),
        ("GET", f"/api/v1/documents/{did}/share-links", None),
        (
            "POST",
            f"/api/v1/documents/{did}/permissions",
            {"json": {"user_id": b.admin.id, "level": "write"}},
        ),
        ("PUT", f"/api/v1/documents/{did}", {"files": {"file": ("a.pdf", PDF, "application/pdf")}}),
    ]
    for method, path, kw in attempts:
        r = await client.request(method, path, headers=b.admin.h, **(kw or {}))
        assert r.status_code == 404, f"{method} {path} -> {r.status_code}"
    # the document is untouched
    still = await client.get(f"/api/v1/documents/{did}", headers=a.admin.h)
    assert still.json()["title"] == "Org A secret merger plan" and still.json()["current_version"] == 1


async def test_cross_tenant_responses_indistinguishable_from_nonexistent(client, two_orgs):
    a, b, doc = two_orgs
    foreign = await client.get(f"/api/v1/documents/{doc['id']}", headers=b.admin.h)
    missing = await client.get(f"/api/v1/documents/{uuid.uuid4()}", headers=b.admin.h)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


async def test_listing_and_search_never_cross_tenants(client, two_orgs):
    a, b, doc = two_orgs
    for params in ({}, {"q": "merger"}, {"tag": "secret"}, {"owner_id": a.admin.id}):
        r = await client.get("/api/v1/documents", headers=b.admin.h, params=params)
        assert r.json()["total"] == 0 and r.json()["items"] == [], params


async def test_admin_of_other_org_has_no_admin_powers_here(client, two_orgs):
    a, b, _ = two_orgs
    assert (
        await client.patch(f"/api/v1/users/{a.admin.id}", headers=b.admin.h, json={"role": "viewer"})
    ).status_code == 404
    users_b = (await client.get("/api/v1/users", headers=b.admin.h)).json()
    assert [u["id"] for u in users_b] == [b.admin.id]
    audit_b = (await client.get("/api/v1/audit", headers=b.admin.h)).json()
    assert all(i["org_id"] == b.org_id for i in audit_b["items"])
    assert (await client.get("/api/v1/audit", headers=b.admin.h, params={"user_id": a.admin.id})).json()["total"] == 0
    assert (await client.get("/api/v1/audit", headers=b.admin.h, params={"resource_id": two_orgs[2]["id"]})).json()[
        "total"
    ] == 0


async def test_cannot_grant_access_to_user_of_another_org(client, new_org):
    a, b = await new_org(), await new_org()
    doc = (await upload(client, a.admin)).json()
    r = await client.post(
        f"/api/v1/documents/{doc['id']}/permissions",
        headers=a.admin.h,
        json={"user_id": b.admin.id, "level": "read"},
    )
    assert r.status_code == 404
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=b.admin.h)).status_code == 404


async def test_share_token_is_bound_to_its_tenant(client, two_orgs):
    a, b, doc = two_orgs
    token = (await client.post(f"/api/v1/documents/{doc['id']}/share-links", headers=a.admin.h, json={})).json()[
        "token"
    ]
    secret = token.split(".", 1)[1]
    # same secret presented with another tenant's prefix must not resolve
    forged = f"{uuid.UUID(b.org_id).hex}.{secret}"
    r = await client.post(f"/api/v1/shared/{forged}/download", headers={"X-Forwarded-For": next_ip()})
    assert r.status_code == 404
    ok = await client.post(f"/api/v1/shared/{token}/download", headers={"X-Forwarded-For": next_ip()})
    assert ok.status_code == 200


async def test_user_tokens_do_not_work_with_swapped_org_claim(app, client, new_org):
    import jwt

    a, b = await new_org(), await new_org()
    s = app.state.settings
    claims = jwt.decode(a.admin.token, options={"verify_signature": False})
    claims["org_id"] = b.org_id
    forged = jwt.encode(claims, s.jwt_secret.get_secret_value(), "HS256")
    assert (await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {forged}"})).status_code == 401


# ---- database level defence in depth ------------------------------------------------------


async def test_rls_hides_rows_without_tenant_context(app_engine, client, two_orgs):
    """Even a bug that forgets WHERE org_id=... cannot read data: the runtime role sees no rows
    unless the transaction is bound to a tenant."""
    a, b, doc = two_orgs
    async with app_engine.connect() as c:
        assert (await c.execute(text("SELECT count(*) FROM documents"))).scalar_one() == 0
        await c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": b.org_id})
        assert (await c.execute(text("SELECT count(*) FROM documents WHERE id=:d"), {"d": doc["id"]})).scalar_one() == 0
        assert (
            await c.execute(text("SELECT count(*) FROM audit_logs WHERE org_id=:o"), {"o": a.org_id})
        ).scalar_one() == 0
    async with app_engine.connect() as c:
        await c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": a.org_id})
        assert (await c.execute(text("SELECT count(*) FROM documents WHERE id=:d"), {"d": doc["id"]})).scalar_one() == 1


async def test_rls_blocks_writes_into_another_tenant(app_engine, two_orgs):
    a, b, doc = two_orgs
    async with app_engine.connect() as c:
        await c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": b.org_id})
        with pytest.raises(DBAPIError, match="row-level security"):
            await c.execute(
                text("INSERT INTO audit_logs (org_id, action, details) VALUES (:o, 'forged', '{}')"),
                {"o": a.org_id},
            )


async def test_rls_update_and_delete_cannot_touch_other_tenant(app_engine, two_orgs):
    a, b, doc = two_orgs
    async with app_engine.begin() as c:
        await c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": b.org_id})
        assert (await c.execute(text("UPDATE documents SET title='x' WHERE id=:d"), {"d": doc["id"]})).rowcount == 0
        assert (await c.execute(text("DELETE FROM documents WHERE id=:d"), {"d": doc["id"]})).rowcount == 0


async def test_composite_foreign_keys_reject_cross_tenant_references(owner_engine, two_orgs):
    """Even the schema owner (RLS bypass) cannot link rows across organizations."""
    a, b, doc = two_orgs
    async with owner_engine.connect() as c:
        with pytest.raises(IntegrityError, match="fk_permissions_doc_org|fk_permissions_user_org"):
            await c.execute(
                text(
                    "INSERT INTO document_permissions (id, org_id, document_id, user_id, level, granted_by) "
                    "VALUES (gen_random_uuid(), :b, :d, :u, 'read', :u)"
                ),
                {"b": b.org_id, "d": doc["id"], "u": b.admin.id},
            )
    async with owner_engine.connect() as c:
        with pytest.raises(IntegrityError, match="fk_permissions_user_org"):
            await c.execute(
                text(
                    "INSERT INTO document_permissions (id, org_id, document_id, user_id, level, granted_by) "
                    "VALUES (gen_random_uuid(), :a, :d, :u, 'read', :u)"
                ),
                {"a": a.org_id, "d": doc["id"], "u": b.admin.id},
            )


async def test_runtime_role_is_not_privileged(app_engine):
    async with app_engine.connect() as c:
        row = (await c.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).one()
        assert tuple(row) == (False, False)
        with pytest.raises(DBAPIError, match="must be owner"):
            await c.execute(text("DROP TABLE documents"))


async def test_audit_log_is_append_only(app_engine, owner_engine, two_orgs):
    a, _, _ = two_orgs
    async with app_engine.connect() as c:
        await c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": a.org_id})
        with pytest.raises(DBAPIError, match="permission denied"):
            await c.execute(text("UPDATE audit_logs SET action='tampered'"))
    async with app_engine.connect() as c:
        with pytest.raises(DBAPIError, match="permission denied"):
            await c.execute(text("DELETE FROM audit_logs"))
    async with owner_engine.connect() as c:  # even the owner is stopped by the trigger
        with pytest.raises(DBAPIError, match="append-only"):
            await c.execute(text("UPDATE audit_logs SET action='tampered' WHERE org_id=:o"), {"o": a.org_id})
