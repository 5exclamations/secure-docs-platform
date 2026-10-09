import io
import uuid
import zipfile

import httpx
import pytest
from sqlalchemy import text

from tests.conftest import PDF, sha, upload


async def test_upload_download_roundtrip_via_presigned_url(client, new_org):
    org = await new_org()
    r = await upload(
        client,
        org.admin,
        PDF,
        title="Q3 Report",
        description="quarterly numbers",
        tags="finance,q3",
    )
    assert r.status_code == 201, r.text
    doc = r.json()
    assert doc["current_version"] == 1 and doc["tags"] == ["finance", "q3"]
    assert doc["latest"]["checksum_sha256"] == sha(PDF)

    d = await client.get(f"/api/v1/documents/{doc['id']}/download", headers=org.admin.h)
    assert d.status_code == 200
    body = d.json()
    assert body["sha256"] == sha(PDF) and "X-Amz-Signature" in body["url"] and "X-Amz-Expires=60" in body["url"]
    async with httpx.AsyncClient() as raw:  # no API credentials: the signature alone authorizes
        fetched = await raw.get(body["url"])
    assert fetched.status_code == 200 and fetched.content == PDF
    assert "attachment" in fetched.headers["content-disposition"]


async def test_presigned_url_lifetime_is_short_and_capped(app, client, new_org):
    """The API controls the lifetime it signs. Enforcement of the expiry belongs to the object
    store (AWS S3 / MinIO); moto does not validate signatures, so that part is exercised against
    MinIO by scripts/smoke_compose.py in CI."""
    from urllib.parse import parse_qs, urlparse

    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    url = (await client.get(f"/api/v1/documents/{doc['id']}/download", headers=org.admin.h)).json()["url"]
    q = parse_qs(urlparse(url).query)
    assert q["X-Amz-Expires"] == ["60"] and q["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert q["response-content-type"] == ["application/pdf"]
    from app.config import Settings
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret="x" * 40, presign_ttl_seconds=3600)


async def test_object_key_is_not_user_controlled(owner_engine, client, new_org):
    org = await new_org()
    r = await upload(client, org.admin, filename="../../etc/passwd.pdf")
    doc = r.json()
    assert doc["latest"]["original_filename"] == "passwd.pdf"
    async with owner_engine.connect() as c:
        key = (
            await c.execute(text("SELECT s3_key FROM document_versions WHERE document_id=:d"), {"d": doc["id"]})
        ).scalar_one()
    assert key.startswith(f"{org.org_id}/{doc['id']}/") and "passwd" not in key


@pytest.mark.parametrize(
    ("content", "ctype", "status"),
    [
        (b"<html><script>alert(1)</script></html>", "text/html", 415),
        (b"<svg xmlns='http://www.w3.org/2000/svg'/>", "image/svg+xml", 415),
        (b"MZ\x90\x00 pretend exe", "application/pdf", 415),  # content does not match declared type
        (b"\x89PNG\r\n\x1a\n" + b"0" * 20, "application/pdf", 415),
        (b"binary\x00data", "text/plain", 415),
        (b"", "application/pdf", 400),
    ],
)
async def test_upload_validation(client, new_org, content, ctype, status):
    org = await new_org()
    r = await upload(client, org.admin, content, content_type=ctype)
    assert r.status_code == status, r.text


async def test_ooxml_and_text_uploads_accepted(client, new_org):
    org = await new_org()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<x/>")
    docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert (await upload(client, org.admin, buf.getvalue(), content_type=docx, filename="a.docx")).status_code == 201
    assert (
        await upload(client, org.admin, "héllo,wörld\n".encode(), content_type="text/csv", filename="a.csv")
    ).status_code == 201


async def test_oversize_upload_rejected_while_streaming(make_settings, services, owner_engine, new_org, client):
    from app.main import create_app
    from fastapi import FastAPI

    small = create_app(make_settings(max_upload_bytes=100 * 1024))
    async with small.router.lifespan_context(small):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=small, client=("203.0.113.1", 1)), base_url="http://t")
        org = await new_org()
        tok = org.admin.token  # same JWT secret, same DB
        r = await c.post(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {tok}"},
            files={"file": ("big.pdf", b"%PDF-" + b"0" * (200 * 1024), "application/pdf")},
        )
        assert r.status_code == 413
        ok = await c.post(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {tok}"},
            files={"file": ("ok.pdf", b"%PDF-" + b"0" * 1000, "application/pdf")},
        )
        assert ok.status_code == 201
        await c.aclose()
    assert isinstance(small, FastAPI)


async def test_versions_history_and_download_specific_version(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin, PDF)).json()
    v2 = PDF + b"-second"
    r = await client.put(
        f"/api/v1/documents/{doc['id']}",
        headers=org.admin.h,
        files={"file": ("report-v2.pdf", v2, "application/pdf")},
    )
    assert r.status_code == 200 and r.json()["current_version"] == 2
    versions = (await client.get(f"/api/v1/documents/{doc['id']}/versions", headers=org.admin.h)).json()
    assert [v["version"] for v in versions] == [2, 1]
    old = (await client.get(f"/api/v1/documents/{doc['id']}/versions/1/download", headers=org.admin.h)).json()
    new = (await client.get(f"/api/v1/documents/{doc['id']}/download", headers=org.admin.h)).json()
    async with httpx.AsyncClient() as raw:
        assert (await raw.get(old["url"])).content == PDF
        assert (await raw.get(new["url"])).content == v2
    assert (
        await client.get(f"/api/v1/documents/{doc['id']}/versions/9/download", headers=org.admin.h)
    ).status_code == 404


async def test_metadata_update_and_search(client, new_org):
    org = await new_org()
    a = (
        await upload(
            client,
            org.admin,
            title="Quarterly budget forecast",
            description="finance planning",
            tags="fin",
        )
    ).json()
    await upload(client, org.admin, title="Employee handbook", tags="hr")
    hits = (await client.get("/api/v1/documents", headers=org.admin.h, params={"q": "budget"})).json()
    assert [i["id"] for i in hits["items"]] == [a["id"]]
    assert (await client.get("/api/v1/documents", headers=org.admin.h, params={"q": "planning"})).json()["total"] == 1
    assert (await client.get("/api/v1/documents", headers=org.admin.h, params={"tag": "hr"})).json()["total"] == 1
    assert (
        await client.get("/api/v1/documents", headers=org.admin.h, params={"content_type": "application/pdf"})
    ).json()["total"] == 2
    r = await client.patch(f"/api/v1/documents/{a['id']}", headers=org.admin.h, json={"title": "Renamed ledger"})
    assert r.status_code == 200 and r.json()["title"] == "Renamed ledger"
    assert (await client.get("/api/v1/documents", headers=org.admin.h, params={"q": "budget"})).json()["total"] == 0
    # injection-looking input is just text
    inj = await client.get("/api/v1/documents", headers=org.admin.h, params={"q": "'; DROP TABLE documents;--"})
    assert inj.status_code == 200 and inj.json()["total"] == 0
    extra = await client.patch(
        f"/api/v1/documents/{a['id']}", headers=org.admin.h, json={"owner_id": str(uuid.uuid4())}
    )
    assert extra.status_code == 422  # mass assignment of owner is rejected


async def test_pagination(client, new_org):
    org = await new_org()
    for i in range(5):
        await upload(client, org.admin, title=f"doc {i}")
    p1 = (await client.get("/api/v1/documents", headers=org.admin.h, params={"limit": 2})).json()
    p3 = (await client.get("/api/v1/documents", headers=org.admin.h, params={"limit": 2, "offset": 4})).json()
    assert p1["total"] == 5 and len(p1["items"]) == 2 and len(p3["items"]) == 1
    assert (await client.get("/api/v1/documents", headers=org.admin.h, params={"limit": 1000})).status_code == 422


async def test_soft_delete_and_admin_hard_delete(app, client, new_org):
    org = await new_org()
    editor = await org.add_user("editor")
    doc = (await upload(client, editor)).json()
    assert (await client.delete(f"/api/v1/documents/{doc['id']}?hard=true", headers=editor.h)).status_code == 403
    assert (await client.delete(f"/api/v1/documents/{doc['id']}", headers=editor.h)).status_code == 204
    assert (await client.get(f"/api/v1/documents/{doc['id']}", headers=editor.h)).status_code == 404
    assert (await client.get("/api/v1/documents", headers=editor.h)).json()["total"] == 0
    assert (await client.delete(f"/api/v1/documents/{doc['id']}?hard=true", headers=org.admin.h)).status_code == 204
    acts = [
        i["action"]
        for i in (await client.get("/api/v1/audit", headers=org.admin.h, params={"resource_id": doc["id"]})).json()[
            "items"
        ]
    ]
    assert "document.delete" in acts and "document.hard_delete" in acts  # audit survives deletion


async def test_hard_delete_removes_objects(app, client, new_org, owner_engine):
    import boto3

    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    async with owner_engine.connect() as c:
        key = (
            await c.execute(text("SELECT s3_key FROM document_versions WHERE document_id=:d"), {"d": doc["id"]})
        ).scalar_one()
    s3 = boto3.client(
        "s3",
        endpoint_url=app.state.settings.s3_endpoint_url,
        region_name="us-east-1",
        aws_access_key_id=app.state.settings.s3_access_key_id,
        aws_secret_access_key=app.state.settings.s3_secret_access_key.get_secret_value(),
    )
    s3.head_object(Bucket=app.state.settings.s3_bucket, Key=key)
    await client.delete(f"/api/v1/documents/{doc['id']}?hard=true", headers=org.admin.h)
    with pytest.raises(s3.exceptions.ClientError):
        s3.head_object(Bucket=app.state.settings.s3_bucket, Key=key)


async def test_invalid_ids_do_not_leak_or_crash(client, new_org):
    org = await new_org()
    assert (await client.get("/api/v1/documents/not-a-uuid", headers=org.admin.h)).status_code == 422
    assert (await client.get(f"/api/v1/documents/{uuid.uuid4()}", headers=org.admin.h)).status_code == 404


async def test_download_is_audited(client, new_org):
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    await client.get(f"/api/v1/documents/{doc['id']}/download", headers=org.admin.h)
    items = (await client.get("/api/v1/audit", headers=org.admin.h, params={"action": "document.download"})).json()[
        "items"
    ]
    assert len(items) == 1 and items[0]["resource_id"] == doc["id"] and items[0]["user_id"] == org.admin.id
    assert items[0]["ip"] and items[0]["request_id"]


async def test_presigned_url_expiry_and_tamper_enforced_by_real_store(app, client, new_org, services, owner_engine):
    """Only meaningful against a real S3 implementation (TEST_S3=minio): moto skips signature checks."""
    import asyncio

    if services.s3_kind != "minio":
        pytest.skip("needs TEST_S3=minio (moto does not validate presigned URLs)")
    org = await new_org()
    doc = (await upload(client, org.admin)).json()
    async with owner_engine.connect() as c:
        key = (
            await c.execute(text("SELECT s3_key FROM document_versions WHERE document_id=:d"), {"d": doc["id"]})
        ).scalar_one()
    url = app.state.store.presign_get(key, "x.pdf", "application/pdf", 2)
    other_key = url.replace(key, key[:-1] + ("0" if key[-1] != "0" else "1"))
    async with httpx.AsyncClient() as raw:
        assert (await raw.get(url)).status_code == 200
        assert (await raw.get(other_key)).status_code == 403  # signature binds the object key
        assert (await raw.get(url.replace("X-Amz-Signature=", "X-Amz-Signature=0"))).status_code == 403
        assert (await raw.get(url.split("?")[0])).status_code == 403  # unsigned access is denied
        await asyncio.sleep(3.2)
        assert (await raw.get(url)).status_code == 403  # expired
